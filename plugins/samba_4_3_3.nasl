#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87769);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/29 19:33:19 $");

  script_cve_id(
    "CVE-2015-3223",
    "CVE-2015-5252",
    "CVE-2015-5296",
    "CVE-2015-5299",
    "CVE-2015-5330",
    "CVE-2015-8467"
  );
  script_bugtraq_id(
    79729,
    79731,
    79732,
    79733,
    79734,
    79735
  );
  script_osvdb_id(
    131935,
    131936,
    131937,
    131938,
    131939,
    131940
  );

  script_name(english:"Samba 4.2.x < 4.2.7 / 4.3.x < 4.3.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 4.2.x prior to 4.2.7 or 4.3.x prior to 4.3.3. It is,
therefore, affected by the following vulnerabilities :

  - A denial of service vulnerability exists in the
    ldb_wildcard_compare() function in file ldb_match.c due
    to mishandling certain zero values. An unauthenticated,
    remote attacker can exploit this, via crafted LDAP
    requests, to exhaust CPU resources. (CVE-2015-3223)

  - A security bypass vulnerability exists in the
    check_reduced_name_with_privilege() function and the
    check_reduced_name() function within file smbd/vfs.c
    that allows users to follow symlinks that point to
    resources in another directory that shares a common path
    prefix. An unauthenticated, remote attacker can exploit
    this, via a symlink that points outside of a share, to
    bypass file access restrictions. (CVE-2015-5252)

  - A flaw exists due to a failure to ensure that signing is
    negotiated when creating encrypted connections between
    the client and server. A man-in-the-middle attacker can
    exploit this, by modifying the client-server data
    stream, to downgrade the security of the connection,
    thus allowing communications to be monitored or
    manipulated. (CVE-2015-5296)

  - A security bypass vulnerability exists in the
    shadow_copy2_get_shadow_copy_data() function in file
    modules/vfs_shadow_copy2.c due to a failure to verify
    that DIRECTORY_LIST access rights has been granted when
    accessing snapshots. An unauthenticated, remote attacker
    can exploit this to access snapshots by visiting a
    shadow copy directory. (CVE-2015-5299)

  - A flaw exists in the LDAP server due to improper
    handling of string lengths in LDAP requests. An
    unauthenticated, remote attacker can exploit this to
    gain sensitive information from the daemon heap memory
    by sending crafted packets and then reading an error
    message or a database value. (CVE-2015-5330)

  - The samldb_check_user_account_control_acl() function
    in file dsdb/samdb/ldb_modules/samldb.c fails to
    properly check for administrative privileges during the
    creation of machine accounts. An authenticated, remote
    attacker can exploit this to bypass intended access
    restrictions by making use of a domain that has both
    a Samba DC and Windows DC. (CVE-2015-8467)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2015-3223.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2015-5252.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2015-5296.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2015-5299.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2015-5330.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2015-8467.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.2.7.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.3.3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.2.7 / 4.3.3 or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (lanman =~ '^Samba 4(\\.[23])?$')
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;

# Affected :
# 4.2.x < 4.2.7
# 4.3.x < 4.3.3
if (ver[0] == 4 && ver[1] == 2 && ver[2] < 7)
  fix = '4.2.7';
if (ver[0] == 4 && ver[1] == 3 && ver[2] < 3)
  fix = '4.3.3';

if (fix)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
