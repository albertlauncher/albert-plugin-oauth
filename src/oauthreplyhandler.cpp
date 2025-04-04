// Copyright (c) 2025-2025 Manuel Schneider

#include "oauthreplyhandler.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QUrlQuery>
#include <albert/logging.h>
using namespace Qt::StringLiterals;

namespace {
static QVariantMap urlQueryToVariantMap(const QUrlQuery &query)
{
    QVariantMap values;
    const auto query_items = query.queryItems(QUrl::FullyDecoded);
    for (const auto &item : query_items)
        values.insert(item.first, item.second);
    return values;
}
}

OAuthReplyHandler::OAuthReplyHandler(const QString &url) : callback_url(url) {}

QString OAuthReplyHandler::callback() const { return callback_url; }

void OAuthReplyHandler::handleCallback(const QUrl &url)
{ emit callbackReceived(urlQueryToVariantMap(QUrlQuery(url.query()))); }

void OAuthReplyHandler::networkReplyFinished(QNetworkReply *reply)
{
    if (reply->error() != QNetworkReply::NoError)
    {
        emit tokenRequestErrorOccurred(QAbstractOAuth::Error::NetworkError, reply->errorString());
        return;
    }

    if (reply->header(QNetworkRequest::ContentTypeHeader).isNull())
    {
        emit tokenRequestErrorOccurred(QAbstractOAuth::Error::NetworkError,
                                       u"Empty Content-type header"_s);
        return;
    }

    const QString contentType = reply->header(QNetworkRequest::ContentTypeHeader).isNull()
                                    ? QStringLiteral("text/html")
                                    : reply->header(QNetworkRequest::ContentTypeHeader).toString();

    const QByteArray data = reply->readAll();

    if (data.isEmpty())
    {
        emit tokenRequestErrorOccurred(QAbstractOAuth::Error::NetworkError, u"No received data"_s);
        return;
    }

    emit replyDataReceived(data);

    QVariantMap ret;
    if (contentType.startsWith(QStringLiteral("text/html"))
        || contentType.startsWith(QStringLiteral("application/x-www-form-urlencoded")))
        ret = urlQueryToVariantMap(QUrlQuery(QString::fromUtf8(data)));

    else if (contentType.startsWith(QStringLiteral("application/json"))
             || contentType.startsWith(QStringLiteral("text/javascript")))
    {
        const QJsonDocument document = QJsonDocument::fromJson(data);
        if (!document.isObject())
        {
            emit tokenRequestErrorOccurred(QAbstractOAuth::Error::ServerError,
                                           u"Received data is not a JSON object: %1"_s.arg(
                                               QString::fromUtf8(data)));
            return;
        }

        const QJsonObject object = document.object();

        if (object.isEmpty())
            WARN << "Received empty JSON object: " << QString::fromUtf8(data);

        ret = object.toVariantMap();
    }

    else
    {
        emit tokenRequestErrorOccurred(QAbstractOAuth::Error::ServerError,
                                       u"Unknown Content-type %1"_s.arg(contentType));
        return;
    }

    emit tokensReceived(ret);
}
