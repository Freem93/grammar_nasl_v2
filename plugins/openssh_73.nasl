#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93194);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2016-6515", "CVE-2016-6210");
  script_bugtraq_id(92212);
  script_osvdb_id(141586, 142342, 142343, 142344);

  script_name(english:"OpenSSH < 7.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 7.3. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists that is due to the program returning
    shorter response times for authentication requests with
    overly long passwords for invalid users than for valid
    users. This may allow a remote attacker to conduct a
    timing attack and enumerate valid usernames.
    (CVE-2016-6210)

  - A denial of service vulnerability exists in the
    auth_password() function in auth-passwd.c due to a
    failure to limit password lengths for password
    authentication. An unauthenticated, remote attacker can
    exploit this, via a long string, to consume excessive
    CPU resources, resulting in a denial of service
    condition. (CVE-2016-6515)

  - An unspecified flaw exists in the CBC padding oracle
    countermeasures that allows an unauthenticated, remote
    attacker to conduct a timing attack. (VulnDB 142343)

  - A flaw exists due to improper operation ordering of MAC
    verification for Encrypt-then-MAC (EtM) mode transport
    MAC algorithms when verifying the MAC before decrypting
    any ciphertext. An unauthenticated, remote attacker can
    exploit this, via a timing attack, to disclose sensitive
    information. (VulnDB 142344)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.3");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=openbsd-announce&m=147005433429403");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/" + port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner)
  audit(AUDIT_NOT_LISTEN, "OpenSSH", port);
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);
if (backported)
  audit(code:0, AUDIT_BACKPORT_SERVICE, port, "OpenSSH");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match))
  audit(AUDIT_SERVICE_VER_FAIL, "OpenSSH", port);
version = match[1];

fix = "7.3";
if (
  version =~ "^[0-6]\." ||
  version =~ "^7\.[0-2]"
   )
{
  items = make_array("Version source", banner,
                     "Installed version", version,
                     "Fixed version", fix);
  order = make_list("Version source", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);

}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
