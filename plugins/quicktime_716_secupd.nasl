#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25347);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-2388", "CVE-2007-2389");
  script_bugtraq_id(24221, 24222);
  script_osvdb_id(35575, 35576);

  script_name(english:"QuickTime < 7.1.6 Security Update (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Windows host is less
than 7.1.6.200, the version associated with Apple's Security Update
(QuickTime 7.1.6).  As a result, a remote attacker who can trick a
user on the affected system into opening a malicious Java applet using
QuickTime may be able to execute arbitrary code remotely subject to
the user's privileges or to gain read access to the web browser's
memory." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305531" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2007/May/msg00005.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or apply Apple's Security Update (QuickTime 7.1.6) or
later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/29");
 script_cvs_date("$Date: 2011/04/13 16:19:07 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 7 ||
  (
    iver[0] == 7 &&
    (
      iver[1] < 1 ||
      (
        iver[1] == 1 &&
        (
          iver[2] < 6 ||
          (iver[2] == 6 && iver[3] < 200)
        )
      )
    )
  )
) 
{
  report = string(
    "Version ", ver, " of QuickTime is currently installed\n",
    "on the remote host.\n"
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
