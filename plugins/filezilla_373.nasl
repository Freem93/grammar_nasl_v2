#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69494);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/05 18:31:17 $");

  script_cve_id("CVE-2013-4206", "CVE-2013-4207", "CVE-2013-4208");
  script_bugtraq_id(61644, 61645, 61649);
  script_osvdb_id(96210, 96080, 96081);

  script_name(english:"FileZilla Client < 3.7.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of FileZilla");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of FileZilla Client on the remote host is a version prior
to 3.7.3.  As such, it is affected by multiple vulnerabilities :

  - A buffer underrun vulnerability exists that occurs when
    verifying a DSA signature when using SFTP.
    (CVE-2013-4206)

  - A remote buffer overflow vulnerability exists that is
    triggered when processing a specially crafted DSA
    signature when using SFTP. (CVE-2013-4207)

  - Multiple information disclosure vulnerabilities exist
    due to improper cleaning of private keys used in SFTP
    sessions. An attacker could exploit these issues by
    tricking a user into connecting to a specially crafted
    SFTP server. This can lead to code execution, denial of
    service, and access to sensitive information like SFTP
    login passwords, obsolete session keys, public-key pass
    phrases, and the private halves of public keys.
    (CVE-2013-4208)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2013/q3/291");
  script_set_attribute(attribute:"see_also", value:"https://filezilla-project.org/");
  script_set_attribute(attribute:"see_also", value:"http://trac.filezilla-project.org/ticket/8826");
  script_set_attribute(attribute:"solution", value:"Upgrade to FileZilla Client 3.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:filezilla:filezilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("filezilla_client_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/filezilla/Installed");
  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

appname = "FileZilla Client";
kb_base = "SMB/filezilla/";
port = kb_smb_transport();

fix = "3.7.3";
fixnum = fix;
report = "";
installs = get_kb_item_or_exit(kb_base + "installs");
for (i = 0; i < installs; i++)
{
  path = get_kb_item_or_exit(kb_base + "install/" + i + "/Path");
  ver = get_kb_item_or_exit(kb_base + "install/" + i + "/Version");
  vernum = get_kb_item_or_exit(kb_base + "install/" + i + "/VersionNumber");

  if (ver_compare(ver:vernum, fix:fixnum, strict:FALSE) == -1)
  {
    if (report_verbosity > 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
}

if (report != "")
{
  if (report_verbosity > 0)
    security_warning(port:port, extra:report);
  else
    security_warning(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname);

