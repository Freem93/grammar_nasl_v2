#TRUSTED 7d4e8c7da9432206a41f328b3408e971f3563640f2fb7129cc3156101a2cb80f24f0016607b802c8aa3354b3926b0f6b903164c5f210277b5d459be6f1fe143f0058bb49a64b656f623521251c681c1cefbd86a11f327a03c4b41b236a57e08fab18f4ce7fb075189902c11d6ebda99feccee3c796d7ccfd66e2a058c2d37095898a51f1b7afb8f20360827dae1cf61d5b1943cf685287c0ba673f90ed5bc03417772cee0f61830d074b3a9095fdf60f7195645266bee2cebfc9ccbcdca2c8559d31ce1c9e514b24fa6edd155bdc366c3540a6289db5fee8133bbf90addad6e64152abac96ed52649b07d29ab4591f80f5cbaba16286da0c07a837c72bda62da05df69c61e3ad2022fc787962831cfe56f68f41d72acb05dda45e91e9de5db9e3b6a56d36c411ac9d026c1600919544a4427108302c26cc706f35ca5dd936d1a6af67a1cf3250b037f26e0864999b116da151272b3644f0d8f13d43d22129ca7d2420adcf6b3a9ef8a80d01ad7ba0baa6e22b844052d29756fc22e675a419199987dbc7756f14af92bb1cccacb3fc31965449f75bb2b8f3f2a02d6740bbe9d22e06d5b02740582b5d5e2a3fee1a5d2a014c8aff8d20368e88a0d507e39fbdeff5ce43455e7124af2a43fcdab680fd991338880ba63b76dd5bd19361fbb884acc8976fa8aead58d8eceee5ca2f22671f6fcdcb4d4cb8bdba0d600392f9286316b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80303);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/03");

  script_cve_id("CVE-2014-3513", "CVE-2014-3567");
  script_bugtraq_id(70584, 70586);
  script_osvdb_id(113373, 113374);

  script_name(english:"Tenable SecurityCenter Multiple DoS (TNS-2014-11)");
  script_summary(english:"Checks the version of OpenSSL in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host is
affected by multiple denial of service vulnerabilities in the bundled
OpenSSL library. The library is version 1.0.1 prior to 1.0.1j. It is,
therefore, affected by the following vulnerabilities :

  - A memory leak exists in the DTLS SRTP extension parsing
    code. A remote attacker can exploit this issue, using a
    specially crafted handshake message, to cause excessive
    memory consumption, resulting in a denial of service
    condition. (CVE-2014-3513)

  - A memory leak exists in the SSL, TLS, and DTLS servers
    related to session ticket handling. A remote attacker
    can exploit this, using a large number of invalid
    session tickets, to cause a denial of service condition.
    (CVE-2014-3567)");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2014-11");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/openssl-1.0.1-notes.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20141015.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/SecurityCenter/Version");

  exit(0);
}

include("openssl_version.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
sc_ver = get_kb_item_or_exit("Host/SecurityCenter/Version");
if (! ereg(pattern:"^4\.[6-9]", string:sc_ver)) audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Establish running of local commands
if ( islocalhost() )
{
  if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;
}

fix = "1.0.1j";
pattern = "OpenSSL (\d+(?:\.\d+)*(-beta\d+|[a-z]*))";

# Check version
line = info_send_cmd(cmd:"/opt/sc4/support/bin/openssl version");

if (! line) audit(AUDIT_VER_FAIL, "/opt/sc4/support/bin/openssl");
match = eregmatch(pattern:pattern, string:line);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, line);
version = match[1];

# Check if vulnerable. Same branch only flags if the 1.0.1 matches,
# min check makes betas not vuln.
if (openssl_ver_cmp(ver:version, fix:fix, same_branch:TRUE, is_min_check:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version         : ' + sc_ver +
    '\n  SecurityCenter OpenSSL version : ' + version +
    '\n  Fixed OpenSSL version          : ' + fix +
    '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OpenSSL (within SecurityCenter)", version);
