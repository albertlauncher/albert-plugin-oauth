// Copyright (c) 2025-2025 Manuel Schneider

#pragma once
#include "oauth.h"
#include <QObject>
#include <albert/extensionplugin.h>
#include <albert/urlhandler.h>
#include <map>
class Authorization;


class Plugin : public albert::ExtensionPlugin,
               public albert::plugin::oauth::IPlugin,
               private albert::UrlHandler
{
    ALBERT_PLUGIN
    using IAuthorization = albert::plugin::oauth::IAuthorization;

public:

    Plugin();

    QWidget *buildConfigWidget() override;

    IAuthorization *authorize(IAuthorization::Configuration configuration) override;

private:

    void handle(const QUrl &) override;

    const QString callback_url;
    std::map<QString, Authorization*> authorizations;

};
