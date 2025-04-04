// Copyright (c) 2025-2025 Manuel Schneider

#pragma once
#include "oauth.h"
#include "oauthreplyhandler.h"
#include <QOAuth2AuthorizationCodeFlow>

const auto OAUTH_CALLBACK_KEY = "redirect_uri";

class Authorization final : public albert::plugin::oauth::IAuthorization
{
public:
    Authorization(const QString &name,
                  const QString &client_id,
                  const QString &client_secret,
                  const QString &scope,
                  const QString &auth_url,
                  const QString &token_url,
                  const QString &callback_url,
                  const QString &refresh_token = {});

    void request() override;
    State state() const override;
    const std::optional<Error> &error() const override;
    QString token() const override;

    QString name;
    QOAuth2AuthorizationCodeFlow oauth;
    OAuthReplyHandler reply_handler;
    State state_;
    std::optional<Error> error_;

};
