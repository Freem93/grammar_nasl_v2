#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25764);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-3969");
  script_bugtraq_id(24989);
  script_osvdb_id(37979);

  script_name(english:"Panda Antivirus EXE File Parsing Overflow");
  script_summary(english:"Checks version of Panda Antivirus signatures"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is prone to a buffer
overflow attack." );
 script_set_attribute(attribute:"description", value:
"The version of Panda Antivirus installed on the remote host reportedly
contains a buffer overflow in its file parsing engine.  Using a
specially crafted EXE file, a remote attacker may be able to leverage
this issue to crash the affected application or to execute arbitrary
code." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/474247/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Use the Update feature to update the virus signatures to a version
issued on or after July 20, 2007." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/21");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/07/20");
 script_cvs_date("$Date: 2016/05/16 14:22:05 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:pandasecurity:panda_antivirus");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("panda_antivirus_installed.nasl");
  script_require_keys("Antivirus/Panda/installed", "Antivirus/Panda/sigs");

  exit(0);
}


# Get the signature database update for the target.
sigs = get_kb_item("Antivirus/Panda/sigs");
if (!sigs) exit(0);
if (sigs !~ "^[0-9]+-[0-9]+-[0-9]+$") exit(0);


# There's a problem if the update is before 7-20-2007.
p = split(sigs, sep:"-", keep:FALSE);
for (i=0; i<max_index(p); i++)
  p[i] = int(p[i]);

if (
  p[2] < 2007 ||
  (
    p[2] == 2007 &&
    (
      p[0] < 7 ||
      (p[0] == 7 && p[1] < 20)
    )
  )
)
{
  report = string(
    "\n",
    "The virus signatures currently on the remote host are dated ", sigs, "."
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
