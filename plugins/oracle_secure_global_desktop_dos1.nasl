#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70732);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/10/16 19:52:01 $");

  script_cve_id("CVE-2013-3834");
  script_bugtraq_id(63138);
  script_osvdb_id(98519);

  script_name(english:"Oracle Secure Global Desktop ttaauxserv Remote Denial of Service (remote check)");
  script_summary(english:"Checks version of Oracle Secure Global Desktop");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may be affected by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Oracle Secure Global Desktop
that may have an unspecified denial of service vulnerability in the
ttaauxserv binary.  Note that this may be a false positive, as this
plugin only checks if a vulnerable version of Oracle Secure Global
Desktop is running, and does not check if the patched binary has been
installed."
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(
    attribute:"solution",
    value:
"Install the patched binary per the instructions in the vendor's
advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_secure_global_desktop_http_detect.nbin");
  script_require_keys("www/oracle_sgdadmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Oracle Secure Global Desktop";
port = get_http_port(default:443);

install = get_install_from_kb(appname:"oracle_sgdadmin", port:port, exit_on_fail:TRUE);

dir = install['dir'];

install_url = build_url(port: port, qs:dir);
version = install['ver'];

if (version == "unknown") audit(AUDIT_UNKNOWN_WEB_APP_VER, appname + " Administration Console", install_url);

# we can't detect if patch is installed from version info,
# so we only run this check in paranoid mode
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version != "5.00") audit(AUDIT_INST_VER_NOT_VULN, appname);

build = get_kb_item_or_exit("www/" + port + "/oracle_sgdadmin/Build");

item = eregmatch(pattern:"^([0-9]{8})([0-9]{6})$", string:build);
if (isnull(item)) exit(1, "Unable to parse build number for Oracle Secure Global Desktop.");

if (
  int(item[1]) <= 20130413 && # date
  int(item[2]) <= 131921 # time
)
{
  if (report_verbosity > 0)
  {
    report =
      '\nBased on the self-reported version information from the web administration' +
      '\nconsole, the Oracle Secure Global Desktop install is potentially' +
      '\nvulnerable if the patch hasn\'t been applied : \n' +
      '\n  Version : ' + version + ' (Build ' + build + ')\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version + ' (Build ' + build + ')');
