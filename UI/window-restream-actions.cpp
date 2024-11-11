#include "window-basic-main.hpp"
#include "moc_window-restream-actions.cpp"

#include "obs-app.hpp"

#include <qt-wrappers.hpp>
#include <QToolTip>
#include <QDateTime>
#include <QDesktopServices>
#include <QFileInfo>
#include <QStandardPaths>
#include <QImageReader>

const QString SchedulDateAndTimeFormat = "yyyy-MM-dd'T'hh:mm:ss'Z'";
const QString RepresentSchedulDateAndTimeFormat = "dddd, MMMM d, yyyy h:m";
const QString IndexOfGamingCategory = "20";

OBSRestreamActions::OBSRestreamActions(QWidget *parent, Auth *auth, bool broadcastReady)
	: QDialog(parent),
	  ui(new Ui::OBSRestreamActions),
	  restreamAuth(dynamic_cast<RestreamAuth *>(auth))
//broadcastReady(broadcastReady)
{
	setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
	ui->setupUi(this);

	UpdateOkButtonStatus();

	connect(ui->okButton, &QPushButton::clicked, this, &OBSRestreamActions::BroadcastSelectAndStartAction);
	connect(ui->saveButton, &QPushButton::clicked, this, &OBSRestreamActions::BroadcastSelectAction);
	connect(ui->cancelButton, &QPushButton::clicked, this, [&]() {
		blog(LOG_DEBUG, "Restream live event creation cancelled.");
		reject();
	});

	qDeleteAll(ui->scrollAreaWidgetContents->findChildren<QWidget *>(QString(), Qt::FindDirectChildrenOnly));

	QVector<RestreamEventDescription> events;
	if (!restreamAuth->GetBroadcastInfo(events)) {
		reject();
		return;
	}

	for (auto event : events) {
		ClickableLabel *label = new ClickableLabel();
		label->setTextFormat(Qt::RichText);
		label->setAlignment(Qt::AlignHCenter);
		label->setMargin(4);

		QString scheduledForString;
		if (event.scheduledFor > 0) {
			QDateTime dateTime = QDateTime::fromSecsSinceEpoch(event.scheduledFor);
			scheduledForString = QLocale().toString(
				dateTime, QString("%1 %2").arg(QLocale().dateFormat(QLocale::LongFormat),
							       QLocale().timeFormat(QLocale::ShortFormat)));

			label->setText(QString("<big>%1</big><br>%2: %3")
					       .arg(event.title, QTStr("Restream.Actions.BroadcastScheduled"),
						    scheduledForString));
		} else {
			label->setText(QString("<big>%1</big>%2").arg(event.title, scheduledForString));
		}

		connect(label, &ClickableLabel::clicked, this, [&, label, event]() {
			for (QWidget *i : ui->scrollAreaWidgetContents->findChildren<QWidget *>(
				     QString(), Qt::FindDirectChildrenOnly)) {

				i->setProperty("class", "");
				i->style()->unpolish(i);
				i->style()->polish(i);
			}
			label->setProperty("class", "row-selected");
			label->style()->unpolish(label);
			label->style()->polish(label);

			selectedBroadcastId = event.id;
			UpdateOkButtonStatus();
		});

		ui->scrollAreaWidgetContents->layout()->addWidget(label);
	}
}

OBSRestreamActions::~OBSRestreamActions() {}

void OBSRestreamActions::UpdateOkButtonStatus()
{
	bool enable = !selectedBroadcastId.isEmpty();
	ui->okButton->setEnabled(enable);
	ui->saveButton->setEnabled(enable);
}

void OBSRestreamActions::BroadcastSelectAction()
{
	QString streamKey;
	if (!restreamAuth->GetBroadcastKey(selectedBroadcastId, streamKey)) {
		return;
	}

	emit ok(QT_TO_UTF8(selectedBroadcastId), QT_TO_UTF8(streamKey), false);
	accept();
}

void OBSRestreamActions::BroadcastSelectAndStartAction()
{
	QString streamKey;
	if (!restreamAuth->GetBroadcastKey(selectedBroadcastId, streamKey)) {
		return;
	}

	emit ok(QT_TO_UTF8(selectedBroadcastId), QT_TO_UTF8(streamKey), true);
	accept();
}
