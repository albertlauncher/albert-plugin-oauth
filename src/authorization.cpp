// Copyright (c) 2025-2025 Manuel Schneider

#include "authorization.h"
#include <QDesktopServices>
#include <QNetworkRequest>
#include <QTimer>
#include <albert/logging.h>
using QOAuth = QOAuth2AuthorizationCodeFlow;
using namespace Qt::StringLiterals;
using namespace albert::plugin::oauth;
using namespace std;

IAuthorization::~IAuthorization() = default;

Authorization::Authorization(const QString &_name,
                             const QString &_client_id,
                             const QString &_client_secret,
                             const QString &_scope,
                             const QString &_auth_url,
                             const QString &_token_url,
                             const QString &_callback_url,
                             const QString &_refresh_token) :
    name(_name),
    reply_handler(_callback_url),
    state_(State::None)
{
    oauth.setReplyHandler(&reply_handler);
    oauth.setClientIdentifier(_client_id);
    oauth.setClientIdentifierSharedKey(_client_secret);
    oauth.setAuthorizationUrl(QUrl(_auth_url));
    oauth.setAccessTokenUrl(QUrl(_token_url));
    oauth.setScope(_scope);
    oauth.setModifyParametersFunction([&](QOAuth::Stage stage,
                                          QMultiMap<QString, QVariant> *parameters) {
        if (stage == QOAuth::Stage::RequestingAuthorization) {
            parameters->insert(OAUTH_CALLBACK_KEY, _callback_url);
        }
    });
    if (!_refresh_token.isEmpty())
    {
        state_ = State::Granted;
        oauth.setRefreshToken(_refresh_token);
        oauth.refreshAccessToken();
    }

    QObject::connect(&oauth, &QOAuth::authorizeWithBrowser,
                     this, &QDesktopServices::openUrl);

    QObject::connect(&oauth, &QOAuth::tokenChanged,
                     this, &Authorization::tokenChanged);

    QObject::connect(&oauth, &QOAuth::requestFailed, this, [this](const QOAuth::Error error){
        WARN << name << "request failed:" << (int)error;
        state_ = State::None;
        emit stateChanged(state_);
    });

    QObject::connect(&oauth, &QOAuth::error, this, [this](const QString &error,
                                                          const QString &errorDescription,
                                                          const QUrl &uri){
        WARN << name << "error:" << oauth.accessTokenUrl().toString() << error << errorDescription << uri;
        state_ = State::None;
        error_ = {
            .name=error,
            .description=errorDescription,
            .info_url=uri.toString()
        };
        emit stateChanged(state_);
    });

    QObject::connect(&oauth, &QOAuth::granted, this, [this]{
        INFO << name << "access granted!";
        state_ = State::Granted;
        error_ = {};
        emit stateChanged(state_);
    });

    QObject::connect(&oauth, &QOAuth::expirationAtChanged, this, [this](const QDateTime &expiresAt){
        auto refreshAt = expiresAt.addSecs(-10); // 30 seks before expiration
        DEBG << name
             << "access token expires at:" << expiresAt.toString("hh:mm:ss")
             << "refreshing at:" << refreshAt.toString("hh:mm:ss");
        QTimer::singleShot(QDateTime::currentDateTime().msecsTo(refreshAt),
                           &oauth, &QOAuth::refreshAccessToken);
    });
}

void Authorization::request()
{
    if (state_ != State::Granted)
    {
        state_ = State::Awaiting;
        emit stateChanged(state_);
        oauth.grant();
    }
}

const optional<IAuthorization::Error> &Authorization::error() const { return error_; }

IAuthorization::State Authorization::state() const { return state_; }

QString Authorization::token() const { return oauth.token(); }
