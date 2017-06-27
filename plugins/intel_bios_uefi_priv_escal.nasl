#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(80458);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2015/01/14 15:43:29 $");

 script_cve_id("CVE-2014-8274");
 script_bugtraq_id(71873);
 script_osvdb_id(116356);
 script_xref(name:"CERT", value:"976132");

 script_name(english:"Intel UEFI EFI S3 Resume Boot Path Script Privilege Escalation (INTEL-SA-00041)");
 script_summary(english:"Check the Intel BIOS version.");

 script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to a local privilege escalation attack.");
 script_set_attribute(attribute:"description", value:
"The version of the Intel UEFI BIOS on the remote host is affected by a
privilege escalation vulnerability due to an error, related to
handling the EFI S3 Resume Boot Path boot script, that allows
bypassing firmware write protections. An attacker can exploit this to
perform a reflash of the firmware, read or write to SMRAM memory, or
render the system inoperable.");
 # https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00041&languageid=en-fr
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d508472d");
 # http://media.ccc.de/browse/congress/2014/31c3_-_6129_-_en_-_saal_2_-_201412282030_-_attacks_on_uefi_security_inspired_by_darth_venamis_s_misery_and_speed_racer_-_rafal_wojtczuk_-_corey_kallenberg.html#video
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcc2a010");
 script_set_attribute(attribute:"solution", value:"Upgrade the system BIOS on the remote host.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2014/12/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

 script_dependencies("bios_get_info_ssh.nasl", "bios_get_info_smb_reg.nasl");
 script_require_keys("BIOS/Version", "BIOS/Vendor");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");

vendor = get_kb_item("BIOS/Vendor");
if (vendor !~ "^Intel ") audit(AUDIT_HOST_NOT, "using Intel BIOS");

version = get_kb_item("BIOS/Version");
if (! version) audit(AUDIT_UNKNOWN_DEVICE_VER, "Intel BIOS");

update = "WYLPT10H.86A.0033.2014.1201.0940";
w = split(update,  sep: '.', keep: 0);
v = split(version, sep: '.', keep: 0);

if (max_index(v) < 6) audit(AUDIT_UNKNOWN_APP_VER, "the Intel BIOS");

# Ensure proper "branch" of WYLPT10H.86A
# then check.
# Note that
# https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00019&languageid=en-fr
# says :
# "The 4-digit number after the '86A' or '86I' is the current BIOS version, as in this example: MQ96510H.86A.1663.2007.0319.1957"
# So, we do need to check for < 0033 here as well.
if (v[0] == w[0] && v[1] == w[1])
{
  if (
    (
      int(v[2]) < int(w[2])   # < 0033
    )
    ||
    (
      int(v[2]) == int(w[2])  # < 0033.2014
      &&
      int(v[3]) < int(w[3])
    )
    ||
    (
      int(v[3]) == int(w[3]) &&
      (
        int(v[4]) < int(w[4])
        ||
        (int(v[4]) == int(w[4]) && int(v[5]) < int(w[5]))
      )
    )
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + update +
        '\n';
      security_warning(port:0, extra: report);
    }
    else security_warning(0);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, "The Intel BIOS", version);
