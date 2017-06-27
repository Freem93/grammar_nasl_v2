#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61491);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2012-0409");
  script_bugtraq_id(53682);
  script_osvdb_id(82338);

  script_name(english:"EMC AutoStart ftAgent Multiple Remote Code Execution Vulnerabilities (ESA-2012-020)");
  script_summary(english:"Checks remote version of ftAgent");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an application that is affected by
multiple remote code execution vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of EMC AutoStart on the remote host reportedly contains
multiple remote code execution vulnerabilities :

  - The EMC AutoStart ftAgent, when processing messages with
    opcode 0x32 and subcode 0x04, opcode 0x32 and subcode 0x02,
    opcode 0x03 and subcode 0x04, opcode 0x55 and subcode 0x16,
    opcode 0x55 and subcode 0x01, opcode 0x41 and subcode 0x12,
    opcode 0x32 and subcode 0x3C, opcode 0x32 and subcode 0x2A,
    performs arithmetic on an unvalidated, user-supplied value
    used to determine the size of a new heap buffer. This allows
    a potential integer wrap to cause a heap-based buffer overflow.
    (ZDI-12-116, ZDI-12-117, ZDI-12-118, ZDI-12-120, ZDI-12-121,
    ZDI-12-122, ZDI-12-123, ZDI-12-124, respectively)

  - The EMC AutoStart ftAgent, when processing messages with opcode
    0x41 and subcode 0x00, uses an uninitialized stack variable in 
    calculating a memory pointer. Also, the function uses signed 
    extension and signed comparison when checking the uninitialized
    stack variable, which allows arbitrary negative values to bypass
    the check. This could result in corruption of a controlled memory
    location, which can be leveraged to execute code under the context
    of a privileged user. (ZDI-12-119)

Failed attacks may result in a denial of service."
  );

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/522835");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-116/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-117/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-118/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-119/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-120/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-121/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-122/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-123/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-124/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-159/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-160/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-161/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/281");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/282");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/283");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 5.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:autostart");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("emc_autostart_ftagent_version.nbin");
  script_require_keys("emc/autostart/ftagent/version");
  script_require_ports("Services/emc-autostart-ftagent", 8045);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');


#
# We don't have patch for ESA-2012-020, thus rely on remote version check
#
ver_str = get_kb_item_or_exit('emc/autostart/ftagent/version');
port = get_service(ipproto:'TCP',svc:"emc-autostart-ftagent", default:8045, exit_on_fail:TRUE);

#
# We don't know the exact version of the patched ftAgent,
# but the ESA-2012-020 advisory says it should be 5.4.3

# AutoStart 5.3 and older
# format: "5.3 SP4"
if (ver_str =~ "^ *[1-5]\.[0-3][^0-9]")
{
  security_hole(port);
}
# 5.4 and higher
# format: "5.4.1 build 73"
else
{
  arr = eregmatch(string:ver_str, pattern:'([0-9.]+) +build +([0-9]+)');
  if(!isnull(arr))
  {
    ver = arr[1];
    fields = split(ver, sep:'.');
    if (max_index(fields) == 3)
    {
      if (ver_compare(ver:ver, fix:'5.4.3') < 0) security_hole(port);
      else audit(AUDIT_LISTEN_NOT_VULN, 'EMC AutoStart ftAgent', port);
      exit(0);
    }
  }
  exit(1, "Unexpected format for AutoStart ftAgent version string '"+ver_str+"'.");
}
