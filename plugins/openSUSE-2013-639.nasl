#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-639.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75111);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-2625", "CVE-2013-2637", "CVE-2013-3551", "CVE-2013-4088", "CVE-2013-4717", "CVE-2013-4718");
  script_osvdb_id(92086, 92087, 93628, 94436, 95014, 95015);

  script_name(english:"openSUSE Security Update : otrs (openSUSE-SU-2013:1338-1)");
  script_summary(english:"Check for the openSUSE-2013-639 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ticket system OTRS was updated to 3.1.18 to fix various bugs and
security issues.

Update to 3.1.18 :

  - OSA-2013-05, CVE-2013-4717, CVE-2013-4718 fixed.

  - Fixed bug#9561 - ACL restriction with CustomerID for
    DynamicFields at new Ticket screen not working.

  - Fixed bug#9425 - Wrong created date for queue view.

  - Fixed bug#9125 - AgentTicketSearch dialog does not
    expand when choosing more search criteria.

  - Fixed bug#8273 - Copying text in preview mode not
    possible.

  - Fixed bug#9557 - Cannot see quoted text in customer
    ticket zoom.

  - Fixed bug#9011 - GenericInterface: New value after value
    mapping can't be 0.

  - Improved parameter quoting in various places.

  - Fixed bug#9104 - Group permission for customer subset
    overwrites permissions for other customers.

  - Fixed bug#8719 - PasswordMin2Lower2UpperCharacters
    problem.

  - 3.1.17

  - Fixed OSA-2013-04, CVE-2013-4088.

  - Improved permission checks in AgentTicketWatcher.

  - Fixed bug#9503 - no connection header in soap responses.

  - Added parameter '-t dbonly' to backup.pl to only backup
    the database

  - Fixed bug#9491 - GenericAgent job update with dynamic
    fields sends Uninitialized value error.

  - Fixed bug#9462 - Package Management page timeout due to
    HTTPS disabled on Proxy connections.

  - 3.1.16

  - Fixed OSA-2013-03, CVE-2013-3551.

  - Updated Package Manager, that will ensure that packages
    to be installed meet the quality standards of OTRS
    Group. This is to guarantee that your package
    wasn&rsquo;t modified, which may possibly harm your
    system or have an influence on the stability and
    performance of it. All independent package contributors
    will have to conduct a check of their Add-Ons by OTRS
    Group in order to take full advantage of the OTRS
    package verification.

  - Fixed bug#9387 - Error in a condition with dynamic
    fields in NotificationEvent.

  - Fixed bug#9286 - Ticket::ChangeOwnerToEveryone isn't
    functional, After a AJAX Load the setting is ignored.

  - Fixed bug#7518 - Escalation Notify by not working
    properly (follow-up fix).

  - Fixed bug#7478 - Got an external answer to an internal
    mail.

  - Improved permission checks in AgentTicketPhone.

  - Fixed
    bug#[9360](http://bugs.otrs.org/show_bug.cgi?id=9360) -
    DynamicField Names shown in CSV output.

  - Fixed bug#9384 - Problem with Method ServiceParentsGet
    of ServiceObject.

  - Fixed bug#9072 - Reply to email-internal includes
    customer users email in Cc. field.

  - 3.1.15

  - Added Malay translation.

  - Fixed bug#8960 - AgentTicketSearch.pm SearchProfile
    problem.

  - Fixed bug#9182 - Customer Search Function -> If you go
    into a ticket and go back you got not the search
    results.

  - Fixed bug#9198 - Linked search with fulltext AND
    additional attributes.

  - Fixed bug#9295 - Article dynamic field is not
    searchable.

  - Fixed bug#9312 - LinkObject permission check problem.

  - 3.1.14

  - Fixed for OSA-2013-01, CVE-2013-2625.

  - Fixed bug#9257 - No notifications to agents with
    out-of-office set but period not reached.

  - Improved permission checks in LinkObject.

  - Fixed bug#9191 - When ticket types are restricted, first
    available type is selected in
    AgentTicketActionCommon-based screens.

  - Updated Turkish translation, thanks to Sefer
    &#x15E;im&#x15F;ek / Network Group!

  - Fixed bug#9214 - IE10: impossible to open links from
    rich text articles.

  - Fixed bug#9218 - Cannot use special characters in
    TicketHook.

  - Fixed bug#9056 - Unused SysConfig option
    Ticket::Frontend::CustomerInfoQueueMaxSize.

  - Follow-up fix for bug#8533 apache will not start on
    Fedora.

  - Fixed bug#9172 - Generic Interface does not work on IIS
    7.0.

  - Updated Czech language translation, thanks to Katerina
    Bubenickova!

  - Fixed bug#8865 - Additional empty data column in
    statistics CSV-Output.

  - update OTRS::ITSM to 3.1.10 (fix for OSA-2013-05,
    CVE-2013-4717, CVE-2013-4718)

  - update OTRS::ITSM to 3.1.9 (fix for OSA-2013-03,
    CVE-2013-3551)

  - update OTRS::ITSM to 3.1.8 (fix for OSA-2013-01,
    CVE-2013-2625) (fix for OSA-2013-02, CVE-2013-2637)

  - update to 3.1.13

  - http://www.otrs.com/en/open-source/community-news/releases-notes/
release-notes-otrs-help-desk-3113/

  - http://source.otrs.org/viewvc.cgi/otrs/CHANGES?revision=1.2260.2.206&view=markup

  - Fixed bug#9162 - Setting the start day of the week for
    the datepicker to Sunday does not work.

  - Fixed bug#9141 - Confused Columns in
    CustomerTicketSearch (ResultShort).

  - Fixed bug#9146 - Signed SMIME mails with altered content
    shows a not clear message.

  - Fixed bug#9145 - SMIME sign verification errors are not
    displayed in TicketZoom.

  - Fixed bug#9140 - Postmaster Filter for empty subjects
    does not work.

  - Fixed bug#9121 - Filenames with Unicode NFD are
    incorrectly reported as NFC by Main::DirectoryRead().

  - Fixed bug#9108 - Check for opened/closed tickets not
    working with Ticket::SubjectFormat = Right.

  - Fixed bug#8839 - DateChecksum followup doesn't get
    correctly SystemID.

  - Updated Russian translation, thanks to Vadim Goncharov!

  - Fixed bug#9101 - Not possible to create dropdown with
    autocomplete attribute.

  - Fixed bug#9096 - All services list is shown instead of
    only default services.

  - Fixed bug#8470 - otrs.GenericAgent.pl reports: Can't
    open
    '/opt/otrs/otrs_vemco/var/tmp/CacheFileStorable/DynamicF
    ield/f3b7e10730fb6c9cab5ae0e7f7e034f3'.

  - Added new translation for Spanish (Colombia), thanks to
    John Edisson Ortiz Roman!

  - Fixed bug#9054 - Link Object deletes all links under
    certain conditions.

  - Fixed bug#8944 - do not backup the cache.

  - Fixed bug#9057 - Generating a PDF with
    bin/otrs.GenerateStats.pl produces lots of warnings.

  - Fixed bug#8929 - Fix problems with empty ticket search
    results while
    Ticket::Frontend::AgentTicketSearch###ExtendedSearchCond
    ition is inactive.

  - Fixed bug#9042 - Add X-Spam-Score to Ticket.xml.

  - Fixed bug#9047 - HistoryTicketGet caches info on disk
    directly.

  - Fixed bug#8923 - Alert message shown, if parent window
    is reloaded while bulk action popup is open.

  - Fixed bug#9030 - Wrong handling of Invalid YAML in
    Scheduler Tasks.

  - Updated CKEditor to version 3.6.6.

  - Updated Polish translation, thanks to Pawel @ ib.pl!

  - Follow-up fix for bug#8805 - Cron missing as RPM
    dependency on RHEL. Changed dependency on 'anacron' to
    'vixie-cron' on RHEL5.

  - Fixed bug#9020 - Generic Ticket Connector does not
    support attachments with ContentType without charset.

  - Fixed bug#8545 - Attachment download not possible if pop
    up of another action is open.

  - Fixed bug#9009 - Empty Multiselect Dynamic Fields
    provokes an error.

  - Fixed bug#8589 - Bulk-Action not possible for single
    ticket.

  - Fixed bug#7198 - Broken repository selection width in
    Package Manager.

  - Fixed bug#8457 - Error if accessing AgentTicketSearch
    from AgentTicketPhone in IE8.

  - Fixed bug#8695 - Table head of Customer Ticket History
    does not resize on window resize.

  - Fixed bug#8533 - Apache will not start if you use
    mod_perl on Fedora 16 or 17.

  - Fixed bug#8974 - Event Based Notification does not
    populate REALNAME with Customer User data.

  - update to 3.1.12

  - Fixed bug#8933 - ArticleStorageInit permission check
    problem.

  - Fixed bug#8763 - Please add charset conversion for
    customer companies.

  - Fixed bug#1970 - Email attachments of type .msg
    (Outlook-Message) are converted.

  - Fixed bug#8955 - Init script might fail on SUSE.

  - Fixed bug#8936 - Ticket close date is empty when ticket
    is created in closed state.

  - Fixed bug#8937 - '$' should be escaped in interpolated
    strings when JavaScript is meant.

  - Fixed bug#8919 - Customer interface search results:
    ticket can only be accessed via ticket number and
    subject.

  - Fixed bug#8850 - CustomerTicketOverview - MouseOver Age
    isn't always correct.

  - Fixed bug#8868 - Event Based Notification problem saving
    'text' Dynamic Fields.

  - Fixed bug#8914 - Syntax error in hash loop in TicketGet
    operation.

  - Fixed bug#8749 - CustomerFrontend: missing dynamicfield
    in search results.

  - Fixed bug#8873 - Bad example of customization of
    'static' dynamic fields in AgentTicketOverviewSmall.

  - Fixed bug#8791 - IMAPTLS fails with some Microsoft
    Exchange servers.

  - Fixed bug#8841 - Search for Dynamic Fields shows all
    tickets (on 'enter' key pressed).

  - Fixed bug#8861 - Ticket History overlaid calender choice
    function.

  - Fixed bug#8862 - GI debugger GUI does not show SOAP XML
    tags correctly.

  - Fixed bug#8566 - Cannot download attachment if filename
    has character #.

  - Fixed bug#8833 - Article table in TicketZoom does not
    scroll correctly.

  - Fixed bug#8673 - Richtext-Editor popups broken on
    Customer-Interface.

  - Fixed bug#8859 - Package upgrade does not work if an
    installed testpackage should be upgraded with a newer
    regular package.

  - Fixed bug#8678 - 'WidgetAction Toggle' is always shown
    as 'Expanded' when nesting elements

  - Fixed bug#8378 - Validation fails if the ID of the
    element contains a dot (.) or a colon (:)

  - Fixed bug#8847 - Inline PGP message description routine
    does not add any info, thanks to IB Development Team.

  - Fixed bug#8848 - AgentTicketEmail does not preserve PGP
    Signatures set if attachment is added.

  - Fixed bug#8149 - Wrong handling of subject when
    SubjectFormat=right.

  - Updated Polish translation, thanks to Pawel!

  - Fixed bug#8820 - Service rcotrs restart fails because a
    race condition happens.

  - Fixed bug#8819 - Syntax error (stop crontab command) in
    SuSE rc script.

  - Removed auto cleanup of expired sessions in
    CreateSessionID() to improve the scalability of the hole
    system.

  - Fixed bug#8667 - TicketSplit does not use QueueID of old
    Ticket for ACL Checking.

  - Fixed bug#8780 - 508 Compliance: Text descriptions of
    'Responsible Tickets' and 'Locked Tickets' links are
    insufficient for screen reader users.

  - Fixed bug#8812 - Encrypted email doesn't see properly in
    Outlook.

  - Fixed bug#8214 - OTRS Init script on Red Hat fails to
    check scheduler.

  - Fixed bug#8850 - Cron missing as RPM dependency on Red
    Hat Enterprise Linux.

  - Fixed bug#7274 - Ticket QueueView sorts by priority on
    first page but subsequent pages sort incorrectly by Age.

  - Fixed bug#8792 - TriggerEscalationStopEvents logs as
    loglevel 'error'.

  - Fixed bug#8743 - AgentTicketCompose.pm creates To, CC,
    BCC filelds without spaces after comma.

  - Fixed bug#8606 - Escalation notifications should not be
    sent to agents who are set out-of-office.

  - Fixed bug#8740 - backup.pl: insufficient handling of
    system() return values.

  - Fixed bug#8622 - Storing a new GI Invoker or Operation
    with an existing name doesn't complain anything.

  - Fixed bug#8770 - AJAX Removes Default Options (follow-up
    fix).

  - Improved caching for Services and Service Lists.

  - Update ITSM to 3.1.7

  - News

  - In AgentTicketZoom the service and the sla are now shown
    as links to the service zoom / sla zoom screens.

  - Updated Polish translation, thanks to Pawel!

  - Added feature in bin/otrs.ITSMConfigItemDelete.pl script
    to delete config items by class together with the
    deployment state.

  - Added CustomerCompany field type that allows to link
    CI's with Customer Companies registered in OTRS.

  - Enhanced Import/Export screen to show a summary after
    importing.

  - Added new optional sysconfig option to check if config
    item names are unique.

  - Added attachment support for ITSM config items. This
    will replace the OTRS FeatureAddOn OTRSCIAttachment.
    Please uninstall this FeatureAddon BEFORE you upgrade to
    OTRS::ITSM 3.1.7 (no attachment data will be lost)!

  - Bug Fixes

  - Bug# 5928 - Print PDF: Newline not interpreted.

  - Bug# 8723 - Setting the planned start and planned end
    time to the same value causes an error.

  - Bug# 8785 - Poor performance of ServiceGet with many
    child services.

  - Bug# 8626 - AgentTicketAddtlITSMField, Ticket states set
    to first state after reload.

  - Bug# 8852 - No Impact and Criticality in
    CustomerTicketZoom.

  - Bug# 7786 - Search by 'type' not displaying correct
    results from page 2 on.

  - Bug# 8804 - Reorder of workorders based on actual
    startime.

  - Bug# 8686 - CI-Search can not handle > 1000 CIs per
    class

  - Bug# 8863 - Problem with ChangeManagement DropDowns in
    Conditions Mask.

  - Bug# 8834 - Broken changes created from template when no
    time offset.

  - Bug# 8830 - CI version header should be clickable in all
    columns.

  - Bug# 8613 - Wrong date if a workorder has been created
    from a template.

  - Bug# 8881 - Searching for a config item number = 0 or a
    config item name = 0 (without wildcards) finds results
    where it should not.

  - Bug# 8882 - Error message from ToolBarMyCAB.

  - Bug# 8614 - Update agent notification doesn't contain
    agent name.

  - Bug# 8615 - Notification not sent for ChangeStateUpdate
    to pending PIR.

  - Bug# 7508 - Autocomplete uses milliseconds rather than
    seconds.

  - rebase perm patch

  - fix changes file"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.otrs.org/show_bug.cgi?id=9360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00027.html"
  );
  # http://source.otrs.org/viewvc.cgi/otrs/CHANGES?revision=1.2260.2.206&view=markup
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0b979b8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.otrs.com/en/open-source/community-news/releases-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828850"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected otrs packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:otrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:otrs-itsm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"otrs-3.1.18-20.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"otrs-itsm-3.1.10-20.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"otrs-3.1.18-26.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"otrs-itsm-3.1.10-26.5.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "otrs");
}
