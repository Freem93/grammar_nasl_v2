#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10866);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2016/06/30 19:55:37 $");

 script_cve_id("CVE-2002-0057");
 script_bugtraq_id(3699);
 script_osvdb_id(3032);
 script_xref(name:"CERT", value:"328163");
 script_xref(name:"MSFT", value:"MS02-008");

 script_name(english:"MS02-008: XML Core Services patch (318203)");
 script_summary(english:"Determines whether the XML Core Services patch Q318202/Q318203 is installed");

 script_set_attribute(attribute:"synopsis", value:"Local files can be retrieved through the web client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Internet Explorer that could
allow an attacker to read local files on the remote host.

To exploit this flaw, an attacker would need to lure a victim on the
remote system into visiting a rogue website.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-008");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the Windows NT, 2000 and
XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/02/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/24");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#deprecated -> FP
exit(0);
