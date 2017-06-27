#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81147);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id(
    "CVE-2014-9328",
    "CVE-2015-1461",
    "CVE-2015-1462",
    "CVE-2015-1463"
  );
  script_bugtraq_id(
    72372,
    72641,
    72652,
    72654
  );
  script_osvdb_id(
    117711,
    117712,
    117713,
    117714,
    117928,
    132125
  );

  script_name(english:"ClamAV < 0.98.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the response to a clamd VERSION command.");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus service running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the ClamAV clamd antivirus daemon on the
remote host is prior to 0.98.6. It is, therefore, affected by the
following vulnerabilities :

  - An out-of-bounds access flaw exists in the unupack()
    function that is triggered when parsing a specially
    crafted Upack packer file. A remote attacker can exploit
    this to crash the application, resulting in a denial of
    service condition. (CVE-2014-9328)

  - An out-of-bounds access flaw exists that is triggered
    when parsing maliciously crafted Yoda Crypter and MEW
    packer files. A remote attacker can exploit this to
    crash the application, resulting in a denial of service
    condition. (CVE-2015-1461)
 
  - An out-of-bounds access flaw exists that is triggered
    when parsing a specially crafted UPX packer file. A
    remote attacker can exploit this to crash the
    application, resulting in a denial of service condition.
    (CVE-2015-1462)

  - A signedness flaw exists in the petite_inflate2x_1to9()
    function in 'libclamav/petite.c' that allows a remote
    attacker with a specially crafted petite packer file
    to cause a denial of service. (CVE-2015-1463)

  - An integer overflow condition exists in upx.c due to
    improper validation of user-supplied input when scanning
    EXE files. An attacker can exploit this to cause a
    heap-based buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.
    (VulnDB 132125)");
  # Release blog
  script_set_attribute(attribute:"see_also", value:"http://blog.clamav.net/2015/01/clamav-0986-has-been-released.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2015/q1/344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=11213");
  script_set_attribute(attribute:"solution", value:"Upgrade to ClamAV 0.98.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/ClamAV/version");
port = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected :
# 0.x < 0.98.6
# 0.98.6beta\d
# 0.98.6rc\d
if (
  (ver[0] == 0 && ver[1] < 98) ||
  (ver[0] == 0 && ver[1] == 98 && ver[2] < 6) ||
  version =~ "^0\.98\.6-(beta|rc)\d($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.98.6' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ClamAV", port, version);
