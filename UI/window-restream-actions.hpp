#pragma once

#include <QDialog>
#include <QString>
#include <QThread>

#include "ui_OBSRestreamActions.h"
#include "auth-restream.hpp"

class OBSRestreamActions : public QDialog {
	Q_OBJECT
	Q_PROPERTY(QIcon thumbPlaceholder READ GetPlaceholder WRITE SetPlaceholder DESIGNABLE true)

	std::unique_ptr<Ui::OBSRestreamActions> ui;

signals:
	void ok(const QString &event_id, const QString &key, const QString &show_id, bool start_now);

protected:
	void UpdateOkButtonStatus();

public:
	explicit OBSRestreamActions(QWidget *parent, Auth *auth, bool broadcastReady);
	virtual ~OBSRestreamActions() override;

	bool Valid() { return valid; };

private:
	void BroadcastSelectAction();
	void BroadcastSelectAndStartAction();
	void OpenRestreamDashboard();

	QIcon GetPlaceholder() { return thumbPlaceholder; }
	void SetPlaceholder(const QIcon &icon) { thumbPlaceholder = icon; }

	RestreamAuth *restreamAuth;
	QString selectedBroadcastId;
	QString selectedShowId;
	bool broadcastReady;
	bool valid = false;
	QIcon thumbPlaceholder;
};
