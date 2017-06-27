#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44071);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2001-0529");
  script_bugtraq_id(2825);
  script_osvdb_id(1853);

  script_name(english:"OpenSSH < 2.9.9 / 2.9p2 Symbolic Link 'cookies' File Removal");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:"Local attackers may be able to delete arbitrary files."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the banner, OpenSSH earlier than 2.9.9 / 2.9p2 is
running on the remote host. Such versions contain an arbitrary file
deletion vulnerability. Due to insecure handling of temporary files, a
local attacker can cause sshd to delete any file it can access named
'cookies'."
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 2.9.9 / 2.9p2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-2.9.9");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-2.9p2");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.org/security.html");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/09/26");
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

port = get_service(svc:"ssh", exit_on_fail:TRUE);

banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

if (version !~ "^[0-9.]+p[0-9]+")
{
  # Pull out numeric portion of version of the native OpenBSD version.
  matches = eregmatch(string:version, pattern:"^([0-9.]+)");
  if (isnull(matches))  exit(1, "Error parsing version ("+version+") from the SSH service listening on port "+port+".");

  fix = "2.9.9";
  if (ver_compare(ver:matches[1], fix:fix, strict:FALSE) >= 0)
    exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");
}
else
{
  # Pull out numeric portion of version of the portable version.
  matches = eregmatch(string:version, pattern:"^([0-9.]+)p([0-9]+)");
  if (isnull(matches))  exit(1, "Error parsing version ("+version+") from the SSH service listening on port "+port+".");

  fix = "2.9p2";
  if (
    (ver_compare(ver:matches[1], fix:"2.9", strict:FALSE) > 0) ||
    (matches[1] == "2.9" && int(matches[2]) >= 2)
  ) exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");
}

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
