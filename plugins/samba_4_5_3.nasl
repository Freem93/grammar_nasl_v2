#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96142);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/31 21:35:24 $");

  script_cve_id("CVE-2016-2123", "CVE-2016-2125", "CVE-2016-2126");
  script_bugtraq_id(94970, 94988, 94994);
  script_osvdb_id(149000, 149001, 149002);

  script_name(english:"Samba 4.3.x < 4.3.13 / 4.4.x < 4.4.8 / 4.5.x < 4.5.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.3.x prior to
4.3.13, 4.4.x prior to 4.4.8, or 4.5.x prior to 4.5.3. It is,
therefore, affected by multiple vulnerabilities :

  - An overflow condition exists in the ndr_pull_dnsp_name()
    function in ndr_dnsp.c that is triggered when handling
    'dnsRecord' attributes of DNS objects. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2016-2123)

  - A flaw exists in the client code when performing
    Kerberos authentication due to always requesting a
    forwardable Kerberos ticket. An adjacent attacker can
    exploit this to cause a service accepting the AP-REQ
    from the client to perform the same actions as the
    client within the Kerberos TGT, allowing the attacker to
    impersonate an authenticated user or service.
    (CVE-2016-2125)

  - A denial of service vulnerability exists in the
    check_pac_checksum() function in kerberos_pac.c due to
    improper handling of the arcfour-hmac-md5 PAC
    (Privilege Attribute Certificate) checksum. An
    authenticated, remote attacker can exploit this to
    corrupt memory, resulting in a crash of the winbindd
    process. (CVE-2016-2126)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2123.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2125.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2126.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.3.13.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.4.8.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.5.3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.3.13 / 4.4.8 / 4.5.3 or later.
Alternatively, apply the vendor-supplied security patch referenced in
the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

version = lanman - 'Samba ';

if (version =~ "^4(\.[3-5])?$")
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

fix = NULL;

regexes = make_array(-2, "a(\d+)", -1, "rc(\d+)");

# Affected :
# Note versions prior to 4.3 are EoL
# 4.3.x < 4.3.13
# 4.4.x < 4.4.8
# 4.5.x < 4.5.3
if (version =~ "^4\.3\.")
  fix = '4.3.13';
else if (version =~ "^4\.4\.")
  fix = '4.4.8';
else if (version =~ "^4\.5\.")
  fix = '4.5.3';

if (!isnull(fix) && ver_compare(ver:version, fix:fix, regexes:regexes) < 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
