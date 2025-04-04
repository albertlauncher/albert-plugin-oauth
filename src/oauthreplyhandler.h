// Copyright (c) 2025-2025 Manuel Schneider

#pragma once
#include <QAbstractOAuthReplyHandler>


class OAuthReplyHandler : public QAbstractOAuthReplyHandler
{
public:

    OAuthReplyHandler(const QString &callback_url);

    void handleCallback(const QUrl &url);

private:

    QString callback() const override;
    void networkReplyFinished(QNetworkReply *reply) override;

    QString callback_url;
};
