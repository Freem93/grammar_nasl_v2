#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(25734);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-3800");
  script_bugtraq_id(24810);
  script_osvdb_id(36116);

  script_name(english:"Symantec SAVCE RTVScan Component Local Privilege Escalation (SYM07-017)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a program that is affected by a local
privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote installation of Symantec Antivirus Corporate Edition
(SAVCE) or Symantec Client Security contains a flaw in the Real-Time
scanner (RTVScan) component because it fails to drop its privileges
with in a threat notification window.  A local attacker may be able to
leverage this flaw to elevate his privileges to SYSTEM level and gain
complete control of the affected system. 

Note that successful exploitation requires that the Notification
Message window be enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2007.07.11c.html" );
 script_set_attribute(attribute:"solution", value:
"SAVCE product branch 9.0 should be be upgraded to 9.0.6.1100 or
better.  SAVCE product branch 10.0 & 10.1 should be upgraded to
10.1.4.4010 or better." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/12");
 script_cvs_date("$Date: 2016/06/13 20:14:28 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

  script_summary(english:"Checks if version of SAVCE");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  exit(0);
}

#

prod_ver = get_kb_item("Antivirus/SAVCE/version");
if(!prod_ver) exit(0);

ver = split(prod_ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if 	(ver[0] == 9)  latest_prod_ver = "9.0.6.1100";
else if (ver[0] == 10) latest_prod_ver = "10.1.4.4010";
else exit(0);

fix = split(latest_prod_ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if (!isnull(fix[i]) && ver[i] < fix[i])
  {
    report = string(
      '\n',
      "Remote product version : ", prod_ver, "\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
    exit(0);
  }
  else if (isnull(fix[i]) || ver[i] > fix[i])
    break;
