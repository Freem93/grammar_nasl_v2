#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62801);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/21 16:17:30 $");

  script_cve_id("CVE-2012-3488", "CVE-2012-3489", "CVE-2012-3525");
  script_bugtraq_id(55072, 55074, 55167);
  script_osvdb_id(84804, 84805, 84929);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2012-09-24-4");

  script_name(english:"Mac OS X : OS X Server < 2.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks OS X Server version.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing an update for OS X Server that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X 10.8 host has a version of OS X Server installed
that is prior to 2.1.1. It is, therefore, affected by the following
vulnerabilities :

  - When the xml2 contrib module is enabled in PostgreSQL,
    an unprivileged database user can read or write
    arbitrary files, subject to the privileges under which 
    the PostgreSQL server runs, when processing specially-
    crafted XSLT documents. (CVE-2012-3488)

  - An unprivileged database user can read arbitrary files,
    subject to the privileges under which the PostgreSQL
    server runs, because 'xml_parse()' attempts to fetch
    external files or URLs as needed to resolve DTD and
    entity references in an XML value. (CVE-2012-3489)

  - A malicious XMPP server can spoof domains via a Verify
    Response or an Authorization Response because the Jabber
    server processes unsolicited XMPP Server Dialback
    responses. (CVE-2012-3525)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5533");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Oct/msg00000.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X Server version 2.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.8([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "2.1.1";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OS X Server", version);
