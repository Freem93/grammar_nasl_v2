#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18560);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-2052");
  script_bugtraq_id(13530);
  script_xref(name:"OSVDB", value:"17576");

  name["english"] = "Rhapsody vidplin.dll AVI Processing Heap Overflow Vulnerability";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia player that is prone to
a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote installation of Rhapsody has a heap overflow in the
'vidplin.dll' file used to process AVI files.  With a specially-
crafted AVI file, an attacker can exploit this flaw to cause arbitrary
code to be run within the context of the affected application when a
user opens the file." );
 script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD20050623.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jun/201" );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/050623_player/EN/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade according to the vendor advisory referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/23");
 script_cvs_date("$Date: 2016/11/02 14:37:09 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/06/23");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  summary["english"] = "Checks for vidplin.dll AVI processing heap overflow vulnerability in Rhapsody";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("rhapsody_detect.nasl");
  script_require_keys("SMB/Rhapsody/Version");

  exit(0);
}


ver = get_kb_item("SMB/Rhapsody/Version");
if (ver) {
  # There's a problem if it's version 3 with a build in [0.815, 0.1141).
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) == 3 &&
    int(iver[1]) == 0 && 
    int(iver[2]) == 0 &&
    (int(iver[3]) >= 815 && int(iver[3]) < 1141)
  ) security_hole(get_kb_item("SMB/transport"));
}
