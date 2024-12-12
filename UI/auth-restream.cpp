#include "moc_auth-restream.cpp"

#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <qt-wrappers.hpp>
#include <json11.hpp>
#include <ctime>
#include <sstream>

#include <obs-app.hpp>
#include "window-dock-browser.hpp"
#include "window-basic-main.hpp"
#include "remote-text.hpp"
#include "ui-config.h"
#include "obf.h"

using namespace json11;

/* ------------------------------------------------------------------------- */

#define RESTREAM_AUTH_URL OAUTH_BASE_URL "v1/restream/redirect"
#define RESTREAM_TOKEN_URL OAUTH_BASE_URL "v1/restream/token"
#define RESTREAM_API_URL "https://api.restream.io/v2/user"
#define RESTREAM_SCOPE_VERSION 1
#define RESTREAM_CHAT_DOCK_NAME "restreamChat"
#define RESTREAM_INFO_DOCK_NAME "restreamInfo"
#define RESTREAM_CHANNELS_DOCK_NAME "restreamChannel"

static Auth::Def restreamDef = {"Restream", Auth::Type::OAuth_StreamKey, false, true};

/* ------------------------------------------------------------------------- */

RestreamAuth::RestreamAuth(const Def &d) : OAuthStreamKey(d) {}

RestreamAuth::~RestreamAuth()
{
	if (!uiLoaded)
		return;

	OBSBasic *main = OBSBasic::Get();

	main->RemoveDockWidget(RESTREAM_CHAT_DOCK_NAME);
	main->RemoveDockWidget(RESTREAM_INFO_DOCK_NAME);
	main->RemoveDockWidget(RESTREAM_CHANNELS_DOCK_NAME);
}

bool RestreamAuth::SetMainChannelKey()
try {
	std::string client_id = RESTREAM_CLIENTID;
	deobfuscate_str(&client_id[0], RESTREAM_HASH);

	if (!GetToken(RESTREAM_TOKEN_URL, client_id, RESTREAM_SCOPE_VERSION))
		return false;
	if (token.empty())
		return false;
	if (!key_.empty())
		return true;

	std::string auth;
	auth += "Authorization: Bearer ";
	auth += token;

	std::vector<std::string> headers;
	headers.push_back(std::string("Client-ID: ") + client_id);
	headers.push_back(std::move(auth));

	std::string output;
	std::string error;
	Json json;
	bool success;

	auto func = [&]() {
		auto url = QString("%1/streamKey").arg(RESTREAM_API_URL);
		success = GetRemoteFile(url.toUtf8(), output, error, nullptr, "application/json", "", nullptr, headers,
					nullptr, 5);
	};

	ExecThreadedWithoutBlocking(func, QTStr("Auth.LoadingChannel.Title"),
				    QTStr("Auth.LoadingChannel.Text").arg(service()));
	if (!success || output.empty())
		throw ErrorInfo("Failed to get stream key from remote", error);

	json = Json::parse(output, error);
	if (!error.empty())
		throw ErrorInfo("Failed to parse json", error);

	error = json["error"].string_value();
	if (!error.empty())
		throw ErrorInfo(error, json["error_description"].string_value());

	key_ = json["streamKey"].string_value();

	return true;
} catch (ErrorInfo info) {
	QString title = QTStr("Auth.ChannelFailure.Title");
	QString text = QTStr("Auth.ChannelFailure.Text").arg(service(), info.message.c_str(), info.error.c_str());

	QMessageBox::warning(OBSBasic::Get(), title, text);

	blog(LOG_WARNING, "%s: %s: %s", __FUNCTION__, info.message.c_str(), info.error.c_str());
	return false;
}

bool RestreamAuth::GetBroadcastInfo(QVector<RestreamEventDescription> &broadcast_out)
try {
	std::string client_id = RESTREAM_CLIENTID;
	deobfuscate_str(&client_id[0], RESTREAM_HASH);

	if (!GetToken(RESTREAM_TOKEN_URL, client_id, RESTREAM_SCOPE_VERSION))
		return false;
	if (token.empty())
		return false;

	std::string auth;
	auth += "Authorization: Bearer ";
	auth += token;

	std::vector<std::string> headers;
	headers.push_back(std::string("Client-ID: ") + client_id);
	headers.push_back(std::move(auth));

	std::string output;
	std::string error;
	Json json;
	bool success;

	auto func = [&]() {
		auto url = QString("%1/events/upcoming?source=2&sort=scheduled").arg(RESTREAM_API_URL);
		success = GetRemoteFile(url.toUtf8(), output, error, nullptr, "application/json", "", nullptr, headers,
					nullptr, 5);
	};

	ExecThreadedWithoutBlocking(func, QTStr("Auth.LoadingChannel.Title"),
				    QTStr("Auth.LoadingChannel.Text").arg(service()));
	if (!success || output.empty())
		throw ErrorInfo("Failed to get upcoming events info from remote", error);

	json = Json::parse(output, error);
	if (!error.empty())
		throw ErrorInfo("Failed to parse json", error);

	error = json["error"].string_value();
	if (!error.empty())
		throw ErrorInfo(error, json["error_description"].string_value());

	auto items = json.array_items();
	for (auto item : items) {
		QString status = QString::fromStdString(item["status"].string_value());
		if (status != "upcoming")
			continue;

		RestreamEventDescription event;
		event.id = QString::fromStdString(item["id"].string_value());
		event.title = QString::fromStdString(item["title"].string_value());
		event.scheduledFor = item["scheduledFor"].is_number() ? item["scheduledFor"].int_value() : 0;
		event.showId = QString::fromStdString(item["showId"].string_value());
		broadcast_out.push_back(event);
	}

	std::sort(broadcast_out.begin(), broadcast_out.end(),
		  [](const RestreamEventDescription &a, const RestreamEventDescription &b) {
			  return a.scheduledFor && (!b.scheduledFor || a.scheduledFor < b.scheduledFor);
		  });

	return true;
} catch (ErrorInfo info) {
	QString title = QTStr("Restream.Actions.BroadcastLoadingFailureTitle");
	QString text = QTStr("Restream.Actions.BroadcastLoadingFailureText")
			       .arg(service(), info.message.c_str(), info.error.c_str());

	QMessageBox::warning(OBSBasic::Get(), title, text);

	blog(LOG_WARNING, "%s: %s: %s", __FUNCTION__, info.message.c_str(), info.error.c_str());
	return false;
}

bool RestreamAuth::GetBroadcastKey(QString id, QString &key_out)
try {
	std::string client_id = RESTREAM_CLIENTID;
	deobfuscate_str(&client_id[0], RESTREAM_HASH);

	if (!GetToken(RESTREAM_TOKEN_URL, client_id, RESTREAM_SCOPE_VERSION))
		return false;
	if (token.empty())
		return false;

	std::string auth;
	auth += "Authorization: Bearer ";
	auth += token;

	std::vector<std::string> headers;
	headers.push_back(std::string("Client-ID: ") + client_id);
	headers.push_back(std::move(auth));

	auto url = QString("%1/events/%2/streamKey").arg(RESTREAM_API_URL, id);

	std::string output;
	std::string error;
	Json json;
	bool success;

	auto func = [&, url]() {
		success = GetRemoteFile(url.toUtf8(), output, error, nullptr, "application/json", "", nullptr, headers,
					nullptr, 5);
	};

	ExecThreadedWithoutBlocking(func, QTStr("Auth.LoadingChannel.Title"),
				    QTStr("Auth.LoadingChannel.Text").arg(service()));
	if (!success || output.empty())
		throw ErrorInfo("Failed to get the event key from remote", error);

	json = Json::parse(output, error);
	if (!error.empty())
		throw ErrorInfo("Failed to parse json", error);

	error = json["error"].string_value();
	if (!error.empty())
		throw ErrorInfo(error, json["error_description"].string_value());

	key_out = QString::fromStdString(json["streamKey"].string_value());

	return true;
} catch (ErrorInfo info) {
	QString title = QTStr("Restream.Actions.BroadcastLoadingFailureTitle");
	QString text = QTStr("Restream.Actions.BroadcastLoadingFailureText")
			       .arg(service(), info.message.c_str(), info.error.c_str());

	QMessageBox::warning(OBSBasic::Get(), title, text);

	blog(LOG_WARNING, "%s: %s: %s", __FUNCTION__, info.message.c_str(), info.error.c_str());
	return false;
}

void RestreamAuth::UseBroadcastKey(QString key, QString show_id)
{
	key_ = key.toUtf8();

	if (chatWidgetBrowser) {
		auto url = QString("https://restream.io/chat-application?show-id=%1").arg(show_id);
		chatWidgetBrowser->setURL(url.toStdString());
	}

	if (titlesWidgetBrowser) {
		auto url = QString("https://restream.io/titles/embed?show-id=%1").arg(show_id);
		titlesWidgetBrowser->setURL(url.toStdString());
	}

	if (channelWidgetBrowser) {
		auto url = QString("https://restream.io/channel/embed?show-id=%1").arg(show_id);
		channelWidgetBrowser->setURL(url.toStdString());
	}
}

void RestreamAuth::SaveInternal()
{
	OBSBasic *main = OBSBasic::Get();
	config_set_string(main->Config(), service(), "DockState", main->saveState().toBase64().constData());
	OAuthStreamKey::SaveInternal();
}

static inline std::string get_config_str(OBSBasic *main, const char *section, const char *name)
{
	const char *val = config_get_string(main->Config(), section, name);
	return val ? val : "";
}

bool RestreamAuth::LoadInternal()
{
	firstLoad = false;
	return OAuthStreamKey::LoadInternal();
}

void RestreamAuth::LoadUI()
{
	if (uiLoaded)
		return;

#ifdef BROWSER_AVAILABLE

	if (!cef)
		return;
	if (!SetMainChannelKey())
		return;

	OBSBasic::InitBrowserPanelSafeBlock();
	OBSBasic *main = OBSBasic::Get();

	std::string url;
	std::string script;

	/* ----------------------------------- */

	url = "https://restream.io/chat-application";

	QSize size = main->frameSize();
	QPoint pos = main->pos();

	BrowserDock *chat = new BrowserDock(QTStr("Auth.Chat"));
	chat->setObjectName(RESTREAM_CHAT_DOCK_NAME);
	chat->resize(420, 600);
	chat->setMinimumSize(200, 300);
	chat->setWindowTitle(QTStr("Auth.Chat"));
	chat->setAllowedAreas(Qt::AllDockWidgetAreas);

	chatWidgetBrowser = cef->create_widget(chat, url, panel_cookies);
	chat->SetWidget(chatWidgetBrowser);

	main->AddDockWidget(chat, Qt::RightDockWidgetArea);

	/* ----------------------------------- */

	url = "https://restream.io/titles/embed";

	BrowserDock *info = new BrowserDock(QTStr("Auth.StreamInfo"));
	info->setObjectName(RESTREAM_INFO_DOCK_NAME);
	info->resize(410, 600);
	info->setMinimumSize(200, 150);
	info->setWindowTitle(QTStr("Auth.StreamInfo"));
	info->setAllowedAreas(Qt::AllDockWidgetAreas);

	titlesWidgetBrowser = cef->create_widget(info, url, panel_cookies);
	info->SetWidget(titlesWidgetBrowser);

	main->AddDockWidget(info, Qt::LeftDockWidgetArea);

	/* ----------------------------------- */

	url = "https://restream.io/channel/embed";

	BrowserDock *channels = new BrowserDock(QTStr("RestreamAuth.Channels"));
	channels->setObjectName(RESTREAM_CHANNELS_DOCK_NAME);
	channels->resize(410, 600);
	channels->setMinimumSize(410, 300);
	channels->setWindowTitle(QTStr("RestreamAuth.Channels"));
	channels->setAllowedAreas(Qt::AllDockWidgetAreas);

	channelWidgetBrowser = cef->create_widget(channels, url, panel_cookies);
	channels->SetWidget(channelWidgetBrowser);

	main->AddDockWidget(channels, Qt::LeftDockWidgetArea);

	/* ----------------------------------- */

	chat->setFloating(true);
	info->setFloating(true);
	channels->setFloating(true);

	chat->move(pos.x() + size.width() - chat->width() - 30, pos.y() + 60);
	info->move(pos.x() + 20, pos.y() + 60);
	channels->move(pos.x() + 20 + info->width() + 10, pos.y() + 60);

	if (firstLoad) {
		chat->setVisible(true);
		info->setVisible(true);
		channels->setVisible(true);
	} else {
		const char *dockStateStr = config_get_string(main->Config(), service(), "DockState");
		QByteArray dockState = QByteArray::fromBase64(QByteArray(dockStateStr));

		if (main->isVisible() || !main->isMaximized())
			main->restoreState(dockState);
	}
#endif

	uiLoaded = true;
}

bool RestreamAuth::RetryLogin()
{
	OAuthLogin login(OBSBasic::Get(), RESTREAM_AUTH_URL, false);
	cef->add_popup_whitelist_url("about:blank", &login);
	if (login.exec() == QDialog::Rejected) {
		return false;
	}

	std::shared_ptr<RestreamAuth> auth = std::make_shared<RestreamAuth>(restreamDef);

	std::string client_id = RESTREAM_CLIENTID;
	deobfuscate_str(&client_id[0], RESTREAM_HASH);

	return GetToken(RESTREAM_TOKEN_URL, client_id, RESTREAM_SCOPE_VERSION, QT_TO_UTF8(login.GetCode()), true);
}

std::shared_ptr<Auth> RestreamAuth::Login(QWidget *parent, const std::string &)
{
	OAuthLogin login(parent, RESTREAM_AUTH_URL, false);
	cef->add_popup_whitelist_url("about:blank", &login);

	if (login.exec() == QDialog::Rejected)
		return nullptr;

	std::shared_ptr<RestreamAuth> auth = std::make_shared<RestreamAuth>(restreamDef);

	std::string client_id = RESTREAM_CLIENTID;
	deobfuscate_str(&client_id[0], RESTREAM_HASH);

	if (!auth->GetToken(RESTREAM_TOKEN_URL, client_id, RESTREAM_SCOPE_VERSION, QT_TO_UTF8(login.GetCode())))
		return nullptr;

	std::string error;
	if (auth->SetMainChannelKey())
		return auth;

	return nullptr;
}

static std::shared_ptr<Auth> CreateRestreamAuth()
{
	return std::make_shared<RestreamAuth>(restreamDef);
}

static void DeleteCookies()
{
	if (panel_cookies) {
		panel_cookies->DeleteCookies("restream.io", std::string());
	}
}

void RegisterRestreamAuth()
{
#if !defined(__APPLE__) && !defined(_WIN32)
	if (QApplication::platformName().contains("wayland"))
		return;
#endif

	OAuth::RegisterOAuth(restreamDef, CreateRestreamAuth, RestreamAuth::Login, DeleteCookies);
}

bool IsRestreamService(const std::string &service)
{
	return service == restreamDef.service;
}
