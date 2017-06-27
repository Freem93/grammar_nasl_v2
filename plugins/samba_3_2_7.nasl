#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35298);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2009-0022");
  script_bugtraq_id(33118);
  script_osvdb_id(51152);
  script_xref(name:"Secunia", value:"33379");

  script_name(english:"Samba 3.2.0 - 3.2.6 Unauthorized Access");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server may be affected by an unauthorized access
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server on the remote
host is between 3.2.0 and 3.2.6 inclusive. Such versions reportedly
allow an authenticated, remote user to gain access to the root
filesystem, subject to his or her privileges, by making a request for
a share called '' (empty string) from a version of smbclient prior to
3.0.28. Successful exploitation of this issue requires 'registry
shares' to be enabled, which is not enabled by default.

Note that Nessus has not actually tried to exploit this issue or to
determine if 'registry shares' is enabled or if the fix has been
applied.");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2009-0022.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.2.7.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 3.2.7 or later or apply the appropriate patch
referenced in the project's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/samba", "SMB/NativeLanManager", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

lanman = get_kb_item("SMB/NativeLanManager");
if (isnull(lanman) || "Samba " >!< lanman) exit(0);

if (ereg(pattern:"Samba 3\.2\.[0-6][^0-9]*$", string:lanman, icase:TRUE))
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote Samba server appears to be :\n",
      "\n",
      "  ", lanman, "\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
