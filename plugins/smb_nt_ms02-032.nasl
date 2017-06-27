#
# (C) Tenable Network Security, Inc.
#

# Fixed in Windows XP SP1
#
# Vulnerable versions :
# 	Media Player in Windows XP preSP1
# 	Media Player 6.4
#	Media Player 7.1
#
# Supercedes MS01-056
#
# @DEPRECATED@

include("compat.inc");

if (description)
{
 script_id(11302);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2016/06/30 19:55:37 $");

 script_cve_id("CVE-2002-0372", "CVE-2002-0373", "CVE-2002-0615");
 script_bugtraq_id(5107, 5109, 5110);
 script_osvdb_id(5312, 5313, 13419);
 script_xref(name:"MSFT", value:"MS02-032");

 script_name(english:"MS02-032: Cumulative patch for Windows Media Player (320920)");
 script_summary(english:"Checks the version of Media Player");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the media
player.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows Media Player is affected by various flaws :

  - A remote attacker may be able to execute arbitrary code
    when sending a badly formed file.

  - A local attacker may gain SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-032");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/06/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_media_player");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

# FP -> superseded by many other patches.
exit(0);
