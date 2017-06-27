#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34993);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2008-4314");
  script_bugtraq_id(32494);
  script_osvdb_id(50230);
  script_xref(name:"Secunia", value:"32813");

  script_name(english:"Samba 3.0.29 - 3.2.4 Potential Memory Disclosure");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server may be affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server on the remote
host is between 3.0.29 and 3.2.4 inclusive. Such versions reportedly
can potentially leak arbitrary memory contents of the 'smbd' process
due to a missing bounds check on client-generated offsets of secondary
'trans', 'trans2', and 'nttrans' requests.

Note that Nessus has not actually tried to exploit this issue or
determine if the fix has been applied.");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2008-4314.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.0.33.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.2.5.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 3.2.5 / 3.0.33 or later or apply the
appropriate patch referenced in the project's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/samba", "SMB/NativeLanManager", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

lanman = get_kb_item("SMB/NativeLanManager");
if (isnull(lanman) || "Samba " >!< lanman) exit(0);

if (ereg(pattern:"Samba 3\.(0\.(29|3[0-2])|2\.[0-4])[^0-9]*$", string:lanman, icase:TRUE))
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
