#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44074);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2004-2069");
  script_bugtraq_id(9040, 14963);
  script_osvdb_id(16567, 75753);

  script_name(english:"Portable OpenSSH < 3.8p1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Remote attackers may be able to cause information to leak from
aborted sessions."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, a version of OpenSSH earlier than 3.8p1 is
running on the remote host and is affected by the following issues:

  - There is an issue in the handling of PAM modules in 
    such versions of OpenSSH.  As a result, OpenSSH may not
    correctly handle aborted conversations with PAM modules. 
    Consequently, that memory may not be scrubbed of 
    sensitive information such as credentials, which could 
    lead to credentials leaking into swap space and core 
    dumps.  Other vulnerabilities in PAM modules could come
    to light because of unpredictable behavior.

  - Denial of service attacks are possible when privilege
    separation is in use. This version of OpenSSH does not
    properly signal non-privileged processes after session
    termination when 'LoginGraceTime' is exceeded. This can
    allow connections to remain open thereby allowing the 
    denial of service when resources are exhausted. 
    (CVE-2004-2069)

");

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 3.8p1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://www.cl.cam.ac.uk/~mgk25/otpw.html#opensshbug");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mindrot.org/show_bug.cgi?id=632");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e86aec66");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb448083");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2f25e5c");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh");

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

# OpenBSD does not use PAM, so this vulnerability only exists in the
# portable version of OpenSSH.
if (version !~ "^[0-9.]+p[0-9]+")
  exit(0, "OpenSSH version "+version+" on port "+port+" is not affected.");

# Pull out numeric portion of version.
matches = eregmatch(string:version, pattern:"^([0-9.]+)");
if (isnull(matches))
  exit(1, 'Failed to parse the version (' + version + ') of the service listening on port '+port+'.');

if (ver_compare(ver:matches[0], fix:"3.8", strict:FALSE) >= 0)
  exit(0, "The Portable OpenSSH server on port "+port+" is not affected as it's version "+version+".");

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 3.8p1' +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
