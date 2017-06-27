#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73470);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_bugtraq_id(56226, 56589);
  script_osvdb_id(
    86590,
    86591,
    86592,
    86593,
    86594,
    87565,
    87566,
    87567
  );

  script_name(english:"Liferay Portal 6.1.x < 6.1 CE GA3 (6.1.2) Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Liferay Portal");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Liferay
Portal running on the remote host is 6.1.x or later but prior to
6.1.2. It is, therefore, potentially affected by multiple
vulnerabilities.

  - A flaw exists where a guest user may view any journal
    structure or template if they know the specific ID of
    that element. (LPS-28550, OSVDB: 87565)

  - A flaw exists with the setupwizard where regardless of
    what is specified when an account is created, a
    test@liferay.com default account with a default password
    is made. This could allow a remote attacker to access
    the program or system and attempt to gain privileged
    access. (LPS-29061, OSVDB: 86593)

  - An unauthorized information disclosure flaw exists due
    to failing to restrict access to private announcements
    when parsing a crafted URL. This could allow a remote
    attacker with a specially crafted URL to gain access to
    potentially sensitive information. (LPS-29148, OSVDB:
    86590)

  - A cross-site scripting flaw exists where input to the
    'comments' field is not validated when requesting
    membership to a restricted site. This could allow a
    remote attacker with a specially crafted request to
    execute arbitrary code within the browser and server
    trust relationship. (LPS-29338, OSVDB: 86591)

  - A flaw exists when handling an organization's permission
    where an omni-admin is a member of an organization. This
    could allow the organization's administrator to rest the
    omni-admin's password. (LPS-30093, OSVDB: 86594)

  - A flaw exists with the document and media portlets where
    user's without permission can create folders and files
    in the root folder. The user can do this by creating the
    folder or file elsewhere and moving it into the root
    folder. (LPS-30437, OSVDB: 87567)

  - A flaw exists where users can be deleted from the
    portal. A remote attacker with a specially constructed
    URL can delete a user if they know that user's email
    address. (LPS-30586, OSVDB: 86592)

  - A flaw exists with the Knowledge Base portlet. A user
    with permission to delete an attachment could delete any
    file on the server, using a specially constructed URL.
    (LPS-30796, OSVDB: 87566)

Note that Nessus has relied only on the self-reported version number
and has not actually tried to exploit these issues or determine if the
associated patches have been applied.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Liferay Portal 6.1.2 or later, or apply the associated
patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(attribute:"see_also", value:"http://www.liferay.com/community/security-team/known-vulnerabilities");
  # http://www.liferay.com/community/security-team/known-vulnerabilities/-/asset_publisher/T8Ei/content/cst-sa-lps-28550-able-to-view-any-journal-structure-template-s-source
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?588a6f8f");
  # http://www.liferay.com/community/security-team/known-vulnerabilities/-/asset_publisher/T8Ei/content/cst-sa-lps-29061-test-liferay-com-created-by-setupwizard-even-when-different-user-specified
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6da0f629");
  # http://www.liferay.com/community/security-team/known-vulnerabilities/-/asset_publisher/T8Ei/content/cst-sa-lps-29148-private-announcements-can-be-viewed-through-announcement-edit
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d3b7d96");
  # http://www.liferay.com/community/security-team/known-vulnerabilities/-/asset_publisher/T8Ei/content/cst-sa-lps-29338-xss-in-group-membership-requests
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65b97697");
  # http://www.liferay.com/community/security-team/known-vulnerabilities/-/asset_publisher/T8Ei/content/cst-sa-lps-30093-organization-administrators-can-change-an-omni-admin-s-password
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?728e0686");
  # http://www.liferay.com/community/security-team/known-vulnerabilities/-/asset_publisher/T8Ei/content/cst-sa-lps-30437-users-without-permission-can-create-folders-files-in-the-root-folder
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebbe8ecd");
  # http://www.liferay.com/community/security-team/known-vulnerabilities/-/asset_publisher/T8Ei/content/cst-sa-lps-30586-able-to-delete-any-user-by-created-url
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23a6e732");
  # http://www.liferay.com/community/security-team/known-vulnerabilities/-/asset_publisher/T8Ei/content/cst-sa-lps-30796-delete-any-file-on-the-server-knowledge-base-
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6b64653");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("www/liferay_portal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);

# Get details of the Liferay Portal install.
install = get_install_from_kb(appname:"liferay_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];
ver = install["ver"];
url = build_url(port:port, qs:dir + "/");

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Liferay Portal", url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Versions 6.1.x < 6.1.2 are vulnerable.
fix = "6.1.2";
if (ver !~ "^6\.1") audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", url, ver);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", url, ver);

# Report our findings.
set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_warning(port:port, extra:report);
