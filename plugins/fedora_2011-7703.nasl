#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-7703.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55007);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 22:15:23 $");

  script_osvdb_id(72842, 72843);
  script_xref(name:"FEDORA", value:"2011-7703");

  script_name(english:"Fedora 13 : phpMyAdmin-3.4.1-1.fc13 (2011-7703)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Welcome to phpMyAdmin 3.4, presenting a new default theme. This
release contains new features, especially :

  - User preferences

    - Relation schema export to multiple formats

    - ENUM/SET editor

    - Simplified interface for export/import

    - AJAXification of some parts

    - Charts

    - Visual query builder

and here is the ChangeLog :

Changes for 3.4.1.0 (2011-05-20)

  - [interface] Synchronize and already configured host

    - [bug] Inline edit and $cfg['PropertiesIconic']

    - [patch] Show a translated label

    - [navi] Table filter is case sensitive

    - [privileges] Revert temporary fix

    - [synchronize] Synchronize and user name

    - [core] Some browsers report an insecure https
      connection

    - [security] Make redirector require valid token (see
      PMASA-2011-3 and PMASA-2011-4)

Changes for 3.4.0.0 (2011-05-11)

  - [view] Enable VIEW rename

    - [privileges] Export a user's privileges

    - [core] Updated mootools to fix some glitches with
      Safari.

    - [interface] Add REGEXP ^...$ to select dialog.

    - [interface] Add insert ignore option to editing row.

    - [interface] Show warning when JavaScript is disabled.

    - [edit] Call UUID function separately to show it in
      insert.

    - [export] Allow export of timestamps in UTC.

    - [core] Remove config data from session as it brings
      chicken-egg problem.

    - [core] Cookie path now honors PmaAbsoluteUri.

    - [core] phpMyAdmin honors https in PmaAbsoluteUri.

    - [core] Try moving tables by RENAME and fail to
      CREATE/INSERT if that fails.

    - [core] Force reload js on code change.

    - [interface] Do not display long numbers in server
      status.

    - [edit] Add option to just display insert query.

    - [interface] Move SSL status to the end, it is usually
      empty.

    - [interface] Show numbers of columns in table
      structure.

    - [inrerface] Add link to reload navigation frame.

    - [auth] Signon authentication forwards error message
      through session data.

    - [interface] Move ^1 to the end of message.

    - [interface] Grey out non applicable actions in
      structure

    - [interface] Allow to create new table from navigation
      frame (in light mode).

    - [browse] Add direct download of binary fields.

    - [browse] Properly display NULL value for BLOB.

    - [edit] Allow to set BLOB to/from NULL with
      ProtectBinary.

    - [edit] Do not default to UNHEX when using file upload.

    - [core] Add option to configure session_save_path.

    - [interface] Provide links to documentation in
      highlighted SQL.

    - [interface] It is now possible to bookmark most pages
      in JS capable browser.

    - [core] Fix SSL detection.

    - [doc] Add some hints to chk_rel.php for quick setup.

    - [interface] Add class to some elements for easier
      theming.

    - [doc] Add some interesting configs to
      config.sample.inc.php.

    - [doc] Added advice to re-login after changing pmadb
      settings

    - [interface] Prefill 'Copy table to' in
      tbl_operations.php, thanks to iinl

    - [lang] Add English (United Kingdom) translation,
      thanks to Robert Readman.

    - [auth] HTTP Basic auth realm name, thanks to Harald
      Jenny

    - [interface] Do not insert doc links to not formatted
      SQL.

    - [lang] Chinese Simplified update, thanks to Shanyan
      Baishui

    - [lang] Turkish update, thanks to Burak Yavuz

    - [interface] Focus TEXTAREA 'sql_query' on click on
      'SQL' link

    - [lang] Uzbek update, thanks to Orzu Samarqandiy

    - [import] After import, also list uploaded filename,
      thanks to Pavel Konnikov and Herman van Rink

    - [structure] Clicking on table name in db Structure
      should Browse the table if possible, thanks to
      bhdouglass

    - [search] New search operators, thanks to Martynas
      Mickeviius

    - [designer] Colored relations based on the primary key,
      thanks to GreenRover

    - [core] Provide way for vendors to easily change paths
      to config files.

    - [interface] Add inline query editing, thanks to
      Muhammd Adnan.

    - [setup] Allow to configure changes tracking in setup
      script.

    - [edit] Optionally disable the Type column, thanks to
      Brian Douglass

    - [edit] Buttons for quicky creating common SQL queries,
      thanks to sutharshan.

    - [interface] Convert loading of export/import to jQuery
      ready event, thanks to sutharshan.

    - [edit] CURRENT_TIMESTAMP is also valid for datetime
      fields.

    - [engines] Fix parsing of PBXT status, thanks to
      Madhura Jayaratne.

    - [interface] Convert upload progress bar to jQuery,
      thanks to Philip Frank.

    - [interface] Add JavaScript validation of datetime
      input, thanks to Sutharshan Balachandren.

    - [interface] Default sort order is now SMART.

    - [interface] Fix flipping of headers in non-IE
      browsers.

    - [interface] Allow to choose servers from configuration
      for synchronisation.

    - [relation] Improve ON DELETE/ON UPDATE drop-downs

    - [relation] Improve labels in relation view

    - [interface] Use jQuery calendar dialog, thanks to
      Muhammad Adnan.

    - [doc] Incorporate synchronisation docs into main
      document.

    - [core] Include Content Security Policy HTTP headers.

    - [CSS] Field attributes use inline CSS

    - [interface] Cleanup navigation frame.

    - [core] Prevent sending of unnecessary cookies, thanks
      to Piotr Przybylski

    - [password] Generate password only available if JS is
      enabled (fixed for Privileges and Change password)

    - [core] RecodingEngine now accepts none as valid
      option.

    - [core] Dropped AllowAnywhereRecoding configuration
      variable.

    - [interface] Define tab order in SQL form to allow
      easier tab navigation.

    - [core] Centralized format string expansion,
      @VARIABLES@ are recommended way now, used by file name
      templates, default queries, export and title
      generating.

    - [validator] SQL validator works also with SOAP PHP
      extension.

    - [interface] Better formatting for SQL validator
      results.

    - [doc] The linked-tables infrastructure is now called
      phpMyAdmin configuration storage.

    - [interface] Move drop/empty links from being tabs to
      Operations tab.

    - [interface] Fixed rendering of error/notice/info
      titles background.

    - [doc] Language and grammar fixes, thanks to Isaac
      Bennetch

    - [export] JSON export, thanks to Hauke Henningsen

    - [interface] Editor for SET/ENUM fields.

    - [interface] Simplified interface to backup/restore.

    - [common] Users preferences

    - [relations] Dropped WYSIWYG-PDF configuration
      variable.

    - [relations] Export relations to Dia, SVG and others

    - [interface] Added charts to status tab, profiling page
      and query results

    - [interface] AJAXification on various pages

    - [core] Remove last remaining parts of profiling code
      which was removed in 2006.

    - [parser] Add workaround for MySQL way of handling
      backtick.

    - [interface] Removed modification options for
      information_schema

    - [config] Add Left frame table filter visibility config
      option, thanks to eesau

    - [core] Force generating of new session on login

    - [interface] Drop page-break-before as it is useless
      for smaller tables.

    - [interface] Allow to wrap enum values.

    - [interface] Do not automatically mark PDF schema rows
      to delete

    - [interface] Do not apply LeftFrameDBSeparator on first
      character.

    - [interface] Column highlighting and marking in table
      view

    - [common] Visual query builder

    - [interface] Prevent long queries from being shown in
      confirmation popup

    - [navi] Left panel table grouping incorrect, thanks to
      garas - garas

    - [interface] Avoid double escaping of MySQL errors.

    - [interface] Use less noisy message and remove disable
      link on server charts and database statistics.

    - [relation] When displaying results, show a link to the
      foreign table even when phpMyAdmin configuration
      storage is not active

    - [relation] Foreign key input options

    - [export] Better handling of export to PHP array.

    - [privileges] No DROP DATABASE warning if you delete a
      user

    - [interface] Add link to documentation for status
      variables.

    - [security] Redirect external links to avoid Referer
      leakage.

    - [interface] Default to not count tables in database.

    - [interface] Shortcut for copying table row.

    - [auth] Reset user cache on login.

    - [interface] Replace hard-coded limit with
      $cfg['LimitChars'].

    - [interface] Indicate that bookmark is being used on
      browse.

    - [interface] Indicate shared bookmarks in interface.

    - [search] Ajaxify browse and delete criteria in DB
      Search, thanks to Thilanka Kaushalya

    - [interface] New default theme pmahomme, dropped
      darkblue_orange theme.

    - [auth] Allow to pass additional parameters using
      signon method.

    - [auth] Add example for OpenID authentication using
      signon method.

    - [dbi] Default to mysqli extension.

    - [interface] Add clear button to SQL edit box.

    - [core] Update library PHPExcel to version 1.7.6

    - [core] Work without mbstring installed.

    - [interface] Add links to variables documentation.

    - [import] Fix import of utf-8 XML files.

    - [auth] Force signon auth on signon URL change.

    - [core] Synchronization does not honor
      AllowArbitraryServer

    - [synchronization] Data containing single quotes
      prevents sync, thanks to jviewer

    - [common] Remove the custom color picker feature

    - [privileges] Don't fail silently on missing priviledge
      to execute REVOKE ALL PRIVILEGES

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=704171"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061319.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?649afa81"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"phpMyAdmin-3.4.1-1.fc13")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
