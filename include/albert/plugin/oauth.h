// Copyright (c) 2024 Manuel Schneider

#pragma once
#include <QObject>
#include <QString>
#include <albert/export.h>
class QNetworkRequest;

namespace albert::plugin::oauth {

class ALBERT_EXPORT IAuthorization : public QObject
{
    Q_OBJECT

public:

    virtual ~IAuthorization();

    struct Configuration {
        const QString name;
        const QString client_id;
        const QString client_secret;
        const QString scope;
        const QString auth_url;
        const QString token_url;
    };

    virtual void request() = 0;

    enum class State { None, Awaiting, Granted };
    virtual State state() const = 0;

    struct Error{
        QString name;
        QString description;
        QString info_url;
    };

    virtual const std::optional<Error> &error() const = 0;

    virtual QString token() const = 0;

signals:

    void stateChanged(State);
    void tokenChanged(const QString &);

};


class ALBERT_EXPORT IPlugin
{
public:

    virtual IAuthorization *authorize(IAuthorization::Configuration) = 0;

protected:

    virtual ~IPlugin() = 0;

};

}

