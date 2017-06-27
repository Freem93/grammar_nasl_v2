#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25933);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_cve_id("CVE-2007-4577", "CVE-2007-4578");
  script_bugtraq_id(25428);
  script_osvdb_id(37986, 37987);

  script_name(english:"Sophos Anti-Virus UPX and BZIP File Multiple Vulnerabilities");
  script_summary(english:"Checks version of Sophos engine");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Sophos Anti-Virus installed on the remote host
reportedly contains several problems involving the processing of 'UPX'
and 'BZIP' files.  If a remote attacker can cause a malicious file to
be scanned by the affected application, these issues could be
leveraged to crash the affected application, fill up space on the disk
volume used for Engine temporary files, or possibly even execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Aug/412");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Aug/437");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Sep/22");
  script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/support/knowledgebase/article/28407.html");
  script_set_attribute(attribute:"solution", value:"Update to Sophos Anti-Virus engine version 2.48.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("sophos_installed.nasl");
  script_require_keys("Antivirus/Sophos/installed", "Antivirus/Sophos/eng_ver");

  exit(0);
}


# Get the signature database update for the target.
engine = get_kb_item("Antivirus/Sophos/eng_ver");
if (!engine) exit(0);

ver = split(engine, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("2.48.0", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if ((ver[i] < fix[i]))
  {
    # nb: Sophos doesn't report the last part in its advisory.
    ver = string(ver[0], ".", ver[1], ".", ver[2]);
    report = string(
      "\n",
      "The current engine version on the remote is ", ver, ".\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
    break;
  }
  else if (ver[i] > fix[i])
    break;
