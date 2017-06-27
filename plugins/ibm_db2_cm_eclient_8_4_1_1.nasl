#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70075);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2009-1231");
  script_bugtraq_id(34326);
  script_osvdb_id(53067);
  script_xref(name:"IAVT", value:"2009-T-0019");

  script_name(english:"IBM DB2 Content Manager eClient < 8.4.1.1 Unspecified Security Vulnerability");
  script_summary(english:"Checks the version of eClient");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a content management application that is
affected by an unspecified vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the IBM DB2 Content Manager eClient
install hosted on the remote web server is a version prior to 8.4.1.1,
and is, therefore, potentially affected by an unspecified security
vulnerability."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27015162");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 8.4.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2_content_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_db2_cm_eclient_detection.nasl");
  script_require_keys("www/ibm_eclient");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname : "ibm_eclient",
  port    : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
version = install["ver"];
install_url = build_url(port:port, qs:dir);

vuln = FALSE;
if (version == UNKNOWN_VER)
{
  if (report_paranoia < 2) audit(AUDIT_PARANOID);
  vuln = TRUE;
}
else
{
  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Versions less than 8.4.1.1 are vulnerable
  if (
    ver[0] < 8 ||
    (ver[0] == 8 && ver[1] < 4) ||
    (ver[0] == 8 && ver[1] == 4 && ver[2] < 1) ||
    (ver[0] == 8 && ver[1] == 4 && ver[2] == 1 && ver[3] < 1)
  ) vuln = TRUE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 8.4.1.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "IBM DB2 Content Manager eClient", install_url, version);
