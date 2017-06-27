#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(97144);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/16 14:43:47 $");

  script_cve_id(
    "CVE-2006-1078",
    "CVE-2006-1079",
    "CVE-2006-4248"
  );
  script_bugtraq_id(
    16972,
    20891
  );
  script_osvdb_id(
    23828,
    30210,
    60381
  );

  script_name(english:"Acme thttpd < 2.26 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Acme thttpd server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Acme thttpd server running
on the remote host is prior to 2.26. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple buffer overflow conditions exist in the
    htpasswd utility. A local attacker can exploit these,
    by calling htpasswd and supplying arbitrary commands
    along with a username to be added to the password file,
    to bypass required authentication and execute arbitrary
    programs with elevated privileges. (CVE-2006-1078)

  - A flaw exists in htpasswd that allows a local attacker
    to gain privileges via shell metacharacters in a command
    line argument, which can then be used to execute other
    commands. (CVE-2006-1079)

  - An unspecified flaw exists that allows a local attacker
    to create or touch arbitrary files via a symlink attack
    on the start_thttpd temporary file. (CVE-2006-4248)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.acme.com/software/thttpd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Acme thttpd version 2.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:acme_labs:thttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("acme_thttpd_detect.nbin");
  script_require_keys("www/thttpd");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = 'Acme thttpd';
port = get_http_port(default:80);

get_kb_item_or_exit('www/'+port+'/acme_thttpd');

# Check if we could get a version
version   = get_kb_item_or_exit('www/'+port+'/acme_thttpd/version', exit_code:1);
source    = get_kb_item_or_exit('www/'+port+'/acme_thttpd/source', exit_code:1);
display_ver = get_kb_item_or_exit('www/'+port+'/acme_thttpd/display_version', exit_code:1);

if (ver_compare(ver:version, fix:"2.26", strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : 2.26' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, display_ver);
