use std::sync::atomic::{AtomicUsize, Ordering};

use actix_session::storage::RedisActorSessionStore;
use actix_session::{Session, SessionMiddleware};
use actix_web::cookie::Key;
use actix_web::http::header;
use actix_web::web::{self, Data};
use actix_web::{App, HttpResponse, HttpServer};
use chrono::{Duration, Utc};
use futures_util::TryStreamExt;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, TokenResponse,
    TokenUrl,
};
use serde::Deserialize;
use tracing_subscriber::EnvFilter;
use wiki::api::{AbuseFilterCheckMatchResponse, AbuseLog, QueryResponse, RequestBuilderExt};
use wiki::req::abuse_filter::{CheckMatch, CheckMatchTest};
use wiki::req::abuse_log::{AbuseLogProp, ListAbuseLog};
use wiki::req::{Action, Limit, QueryList};
use wiki::{Bot, ClientBuilder};

pub struct AppState {
    oauth: BasicClient,
}

#[derive(Deserialize)]
pub struct Auth {
    code: String,
    state: String,
}

#[derive(Deserialize)]
pub struct MaybeAuth {
    #[serde(flatten)]
    auth: Option<Auth>,
}

const INDEX: &str = include_str!("./index.html");

#[actix_web::get("/")]
async fn index(
    session: Session,
    data: web::Data<AppState>,
    q: web::Query<MaybeAuth>,
) -> HttpResponse {
    if session.get::<String>("oauth_key").ok().flatten().is_some() {
        return HttpResponse::Ok().body(INDEX);
    } else if let Some(Auth { code, state }) = q.into_inner().auth {
        let Some(csrf) = session.remove("csrf") else {
            return HttpResponse::Unauthorized().body("CSRF token not found");
        };

        let csrf: String = csrf;
        if csrf != state {
            return HttpResponse::Unauthorized().body("CSRF token mismatch");
        }
        let token = data
            .oauth
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client).await
            .unwrap();
        session
            .insert("oauth_key", token.access_token().secret())
            .unwrap();
        return HttpResponse::Ok().body(INDEX);
    }
    HttpResponse::Ok().body("<h1>Hello World!</h1>")
}

#[actix_web::get("/login")]
async fn login(session: Session, data: web::Data<AppState>) -> HttpResponse {
    let (url, csrf) = &data.oauth.authorize_url(CsrfToken::new_random).url();
    session.insert("csrf", csrf.secret()).unwrap();

    HttpResponse::Found()
        .insert_header((header::LOCATION, url.to_string()))
        .finish()
}

#[derive(serde::Deserialize)]
pub struct GrepRequest {
    code: String,
    filter: String,
}

#[derive(Deserialize, Debug)]
pub struct AbuseLogEntry {
    pub id: u64,
}

pub type ListResponse = QueryResponse<AbuseLog<AbuseLogEntry>>;

async fn grep_inner(site: Bot, req: GrepRequest) -> color_eyre::Result<HttpResponse> {
    let filter_text = req.code;
    let duration = Duration::days(30);
    let q = wiki::req::Query {
        list: Some(
            QueryList::AbuseLog(ListAbuseLog {
                filter: Some(vec![req.filter.clone()]),
                start: None,
                logid: None,
                end: Some((Utc::now() - duration).into()),
                limit: Limit::Value(100),
                prop: AbuseLogProp::IDS,
            })
            .into(),
        ),
        ..Default::default()
    };
    let stream = site.query_all(q).try_filter_map(|x| {
        Box::pin(async { Ok(Some(serde_json::from_value::<ListResponse>(x)?)) })
    });

    let total = AtomicUsize::new(0);
    let matched = AtomicUsize::new(0);

    stream
        .try_for_each(|x| async {
            for entry in x.query.abuse_log {
                let id = entry.id;
                let action = Action::AbuseFilterCheckMatch(CheckMatch {
                    filter: filter_text.clone(),
                    test: CheckMatchTest::LogId(id),
                });
                total.fetch_add(1, Ordering::Relaxed);
                let x: AbuseFilterCheckMatchResponse = site.get(action).send_parse().await?;
                if x.inner.result {
                    matched.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(())
        })
        .await?;

    let total = total.load(Ordering::Relaxed);
    let matched = matched.load(Ordering::Relaxed);

    println!(
        "Over past {:?}, filter {} has matched {total} edits in total, with \
        {matched} edits matching the filter supplied. ({}%)",
        duration.to_std()?,
        req.filter,
        matched as f64 / total as f64 * 100.0,
    );
    Ok(HttpResponse::Ok().body("Hello World"))
}

#[actix_web::post("/grep")]
async fn grep(session: Session, x: web::Form<GrepRequest>) -> HttpResponse {
    let Ok(Some(oauth)) = session.get("oauth_key") else {
        return HttpResponse::Unauthorized().body("Not logged in");
    };

    let oauth: String = oauth;

    let Ok(site) = ClientBuilder::enwiki().oauth(oauth).user_agent("EFGrep Web Service 0.1.0").build().await
    else {
        return HttpResponse::InternalServerError().body("Failed to build client");
    };

    match grep_inner(site, x.into_inner()).await {
        Ok(x) => x,
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}


pub mod constants_prod {
    pub const ADDR: &str = "0.0.0.0:8000";
    pub const REDIS: &str = "redis.svc.tools.eqiad1.wikimedia.cloud:6379";
}

pub mod constants_dev {
    pub const ADDR: &str = "127.0.0.1:8000";
    pub const REDIS: &str = "127.0.0.1:6379";
}

use constants_dev as constants;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    HttpServer::new(|| {
        let oauth = BasicClient::new(
            ClientId::new("1b4826105744657830748cb2483bda49".into()),
            Some(ClientSecret::new(include_str!("../token.secret").into())),
            AuthUrl::new("https://en.wikipedia.org/w/rest.php/oauth2/authorize".into()).unwrap(),
            Some(
                TokenUrl::new("https://en.wikipedia.org/w/rest.php/oauth2/access_token".into())
                    .unwrap(),
            ),
        );
        App::new()
            .app_data(Data::new(AppState { oauth }))
            .wrap(SessionMiddleware::new(
                RedisActorSessionStore::new(constants::REDIS),
                Key::generate(),
            ))
            .service(index)
            .service(login)
            .service(grep)
    })
    .bind(constants::ADDR)
    .unwrap()
    .run()
    .await
    .unwrap();

    Ok(())
}
