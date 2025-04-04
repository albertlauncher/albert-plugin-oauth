// Copyright (c) 2025-2025 Manuel Schneider

#include "authorization.h"
#include "plugin.h"
#include "ui_configwidget.h"
#include <QCoreApplication>
#include <QSettings>
#include <QUrlQuery>
#include <albert/logging.h>
ALBERT_LOGGING_CATEGORY("oauth")
using namespace albert::plugin::oauth;

const auto OAUTH_STATE_KEY    = "state";

IPlugin::~IPlugin() = default;

void Plugin::handle(const QUrl &url)
{
    // Dispath callback url

    QUrlQuery query(url.query());
    const auto identifier = query.queryItemValue(OAUTH_STATE_KEY);

    try {
        authorizations.at(identifier)->reply_handler.handleCallback(url);
    } catch (...) {
        WARN << "Received invalid callback";
    }
}

IAuthorization *Plugin::authorize(IAuthorization::Configuration conf)
{
    auto auth = new Authorization(conf.name,
                                  conf.client_id,
                                  conf.client_secret,
                                  conf.scope,
                                  conf.auth_url,
                                  conf.token_url,
                                  callback_url,
                                  settings()->value(conf.client_id).toString());


    authorizations.emplace(auth->oauth.state(), auth);

    connect(auth, &QObject::destroyed,
            this, [this, auth]{ authorizations.erase(auth->oauth.state()); });

    QObject::connect(&auth->oauth, &QOAuth2AuthorizationCodeFlow::refreshTokenChanged,
                     auth, [this, auth](const QString &refreshToken){
        settings()->setValue(auth->oauth.clientIdentifier(), refreshToken);
    });

    return auth;
}

Plugin::Plugin() : callback_url(QString("%1://%2/").arg(qApp->applicationName(), id())) {}

QWidget* Plugin::buildConfigWidget()
{
    auto* widget = new QWidget();
    Ui::ConfigWidget ui;
    ui.setupUi(widget);

    ui.tableWidget->setColumnCount(3);
    ui.tableWidget->setHorizontalHeaderLabels({"TokenUrl", "State", "Expires"});
    ui.tableWidget->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    ui.tableWidget->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui.tableWidget->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui.tableWidget->verticalHeader()->setVisible(false);
    ui.tableWidget->setShowGrid(false);
    QStringList state_strings({"Awaiting", "Failed","Granted"});

    uint n_rows = 0;
    for (const auto&[state, auth] : authorizations)
    {
        const auto row = n_rows++;
        ui.tableWidget->insertRow(row);

        ui.tableWidget->setItem(row, 0,
                                new QTableWidgetItem(auth->oauth.accessTokenUrl().toString()));

        ui.tableWidget->setItem(row, 1,
                                new QTableWidgetItem(state_strings[(int)auth->state()]));

        ui.tableWidget->setItem(row, 2,
                                new QTableWidgetItem(auth->oauth.expirationAt().toString()));
    }

    return widget;
}
