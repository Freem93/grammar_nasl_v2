#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:014
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17300);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2005-0455", "CVE-2005-0611");
 
 name["english"] = "SUSE-SA:2005:014: RealPlayer";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:014 (RealPlayer).


Two security problems were found in the media player RealPlayer:

- CVE-2005-0455: A buffer overflow in the handling of .smil files.
- CVE-2005-0611: A buffer overflow in the handling of .wav files.

Both buffer overflows can be exploited remotely by providing URLs
opened by RealPlayer.

More informations can be found on this URL:
http://service.real.com/help/faq/security/050224_player/EN/

This updates fixes the problems." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_14_realplayer.html" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'RealNetworks RealPlayer SMIL Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");




 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/09");
 script_cvs_date("$Date: 2013/11/27 17:11:06 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the RealPlayer package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"RealPlayer-10.0.3-0.1", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"RealPlayer-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0455", value:TRUE);
 set_kb_item(name:"CVE-2005-0611", value:TRUE);
}
