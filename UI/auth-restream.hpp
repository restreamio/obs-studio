#pragma once

#include "auth-oauth.hpp"

class BrowserDock;

struct RestreamEventDescription {
	QString id;
	QString title;
	qint64 scheduledFor;
};

class RestreamAuth : public OAuthStreamKey {
	Q_OBJECT

	bool uiLoaded = false;

	virtual bool RetryLogin() override;

	virtual void SaveInternal() override;
	virtual bool LoadInternal() override;

	virtual void LoadUI() override;

public:
	RestreamAuth(const Def &d);
	~RestreamAuth();

	bool SetMainChannelKey();
	bool GetBroadcastInfo(QVector<RestreamEventDescription> &events);
	bool GetBroadcastKey(QString id, QString &key_out);
	void UseBroadcastKey(QString key);

	static std::shared_ptr<Auth> Login(QWidget *parent, const std::string &service_name);
};

bool IsRestreamService(const std::string &service);
