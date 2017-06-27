#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70103);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2008-2499");
  script_bugtraq_id(29328);
  script_osvdb_id(45610);

  script_name(english:"IBM Lotus Sametime Multiplexer Buffer Overflow");
  script_summary(english:"Checks retrieved version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote server hosts an application that contains a buffer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Lotus Sametime STMux.exe on the remote host is prone to
a remote stack-based buffer overflow attack because it fails to properly
bounds-check user-supplied data before copying it to an insufficiently
sized memory buffer."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to version 7.5.1CF2 / 8.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Lotus Domino Sametime STMux.exe Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_sametime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("lotus_sametime_detect.nasl");
  script_require_keys("www/lotus_sametime");
  script_require_ports("Services/www", 80, 8032, 1533);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

get_kb_item_or_exit("www/lotus_sametime/" + port + "/installed");
version = get_kb_item_or_exit("www/lotus_sametime/" + port + "/version");

# Check that version is formatted correctly.
if (version !~ "^[0-9]+(?:\.[0-9]+)+[a-zA-Z0-9]*$") audit(AUDIT_UNKNOWN_WEB_APP_VER, 'IBM Lotus Sametime', build_url(qs:'/', port:port));

# Check for additional info at end of version.
# If it is a CF then use that as part of the version
# comparison.
cf = FALSE;
sub_version = eregmatch(pattern:"^[0-9]+(?:\.[0-9]+)+([a-zA-Z0-9]+)$", string:version);
if (max_index(sub_version) == 2)
{
  sub_version = sub_version[1];
  version = str_replace(string:version, find:sub_version, replace:'');
  if (sub_version =~ "^CF[0-9]+$") cf = TRUE;
}

# IBM version info https://www-304.ibm.com/support/docview.wss?uid=swg21098628
vuln = FALSE;
# fixed 7.5.1CF2
if (ver_compare(ver:version, fix:'7.5.1', strict:FALSE) == 0)
{
  if (!cf || sub_version == "CF1") vuln = TRUE;
}
# Fixed 8.0.1 or higher
else if (ver_compare(ver:version, fix:'8.0.1', strict:FALSE) == -1)
{
  vuln = TRUE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version + sub_version + 
             '\n  Fixed version     : 7.5.1CF2 / 8.0.1' +
             '\n';
    security_hole(port: port, extra: report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM Lotus Sametime", port, version + sub_version);
