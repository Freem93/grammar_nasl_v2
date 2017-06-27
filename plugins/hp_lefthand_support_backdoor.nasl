#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73461);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2013-2352");
  script_bugtraq_id(61070);
  script_osvdb_id(95061);

  script_name(english:"HP StoreVirtual Storage Remote Unauthorized Access");
  script_summary(english:"Checks for the presence of a backdoor");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an SSH service listening that may potentially
allow unauthorized administrative access via a support backdoor
mechanism.");
  script_set_attribute(attribute:"description", value:
"The remote HP storage system running LeftHand OS has an SSH support
backdoor mechanism built in that may allow a remote attacker to gain
root shell access to the system.");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03825537
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32605cee");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches to the device per the vendor's advisory,
and ensure that the remote support functionality is turned off when
not needed.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:lefthand");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("HP/LeftHandOS");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("hp_saniq_hydra.inc");

get_kb_item_or_exit("HP/LeftHandOS");

ports = get_kb_list("Services/ssh");
if (isnull(ports)) ports = make_list(22);
ports = list_uniq(ports);

vuln = FALSE;

foreach port (ports)
{
  sshtext = get_kb_item('SSH/textbanner/'+port);

  if (sshtext =~ "^Support Key: ([0-9A-F]{2}:){5}[0-9A-F]{2}\n$")
  {
    vuln = TRUE;
    security_hole(port);
  }
}

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');
