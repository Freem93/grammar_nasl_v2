#TRUSTED 4e8ece22f5d4f6557cd8ba9373cd43856892b2cab5b07f63252ed37a693b96cc395dcd3b634f162e1de4884eb64f2f464429b8e23a5354bf0c73a891497beb1053cb66344d10cf0ab7303231fa5e43a49315bc7e2e45853b8347293488e774249bd6bff358a44d9e502664d75bbfb47c17656f2d344b20cb438ecbcf95c2033bb86b319dc03c817ddab8ba0960063bf7651b861e382d812d8c4fba558ebead57c37a4c02f40082779d154cc11f7a276ac047abf8f248442554576a80da789353587068a0d2bfbe965a9c86780897409d77d98300ab724346a2626efa964e598ece80d92d8285e650b9d8ec81a133aa80de195bf2262fa9c64054a44d46c67b78eaf5155c4d8413aeaaac7ebacb39ec41d43e20b42b619b3e8028695e71dd1a95910918b9a15ccc427c29bb869c3b5b372009c301b275f744905c0375461c3884447a9719d3248a321da7e424aaa0a1b437890fb34e6fec65dc8eafe32a67eb5a2b2208b8c460abc314e57dd6f5c77d0511d3c8a1b48994ed65901e159b8e7937e721385edeae6df11b06874ddad79235b7f01f15cd596f2c08246186ebc9cb84be774565c5ad2f8ddf376a4078f70da62acbd95f548315e5ac683e0d331991987f69cdc759c38019addbd5a2bdfa8af03ee9f5d6a92a60dde6bfd1b53c5fe1a5c3b4bba7a765a5aedcad6efc416cd80ffff6b55a40e89a969d3bda71dbb4f275
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78035);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3354");
  script_bugtraq_id(70131, 70183);
  script_osvdb_id(112037);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui11547");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-rsvp");

  script_name(english:"Cisco IOS Software RSVP DoS (cisco-sa-20140924-rsvp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in the Resource Reservation Protocol (RSVP)
implementation due to improper handling of RSVP packets. A remote
attacker can exploit this issue by sending specially crafted RSVP
packets to cause the device to reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-rsvp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76088c2b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35621");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCui11547");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-rsvp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCui11547";
fixed_ver = NULL;

#12.0S
if (ver == "12.0(27)S" || ver == "12.0(27)S1" || ver == "12.0(27)S2" || ver == "12.0(27)S2a" || ver == "12.0(27)S2b" || ver == "12.0(27)S2c" || ver == "12.0(27)S2d" || ver == "12.0(27)S3" || ver == "12.0(27)S3a" || ver == "12.0(27)S3b" || ver == "12.0(27)S3c" || ver == "12.0(27)S3d" || ver == "12.0(27)S4" || ver == "12.0(27)S4a" || ver == "12.0(27)S4b" || ver == "12.0(27)S4c" || ver == "12.0(27)S4d" || ver == "12.0(27)S4e" || ver == "12.0(27)S5" || ver == "12.0(27)S5a" || ver == "12.0(27)S5b" || ver == "12.0(27)S5c" || ver == "12.0(27)S5d" || ver == "12.0(27)S5e" || ver == "12.0(28)S" || ver == "12.0(28)S1" || ver == "12.0(28)S1a" || ver == "12.0(28)S1b" || ver == "12.0(28)S2" || ver == "12.0(28)S2a" || ver == "12.0(28)S3" || ver == "12.0(28)S4" || ver == "12.0(28)S4a" || ver == "12.0(28)S4b" || ver == "12.0(28)S4c" || ver == "12.0(28)S4d" || ver == "12.0(28)S4e" || ver == "12.0(28)S4f" || ver == "12.0(28)S4g" || ver == "12.0(28)S5" || ver == "12.0(28)S5a" || ver == "12.0(28)S5b" || ver == "12.0(28)S5c" || ver == "12.0(28)S5d" || ver == "12.0(28)S5e" || ver == "12.0(28)S6" || ver == "12.0(28)S6a" || ver == "12.0(28)S6b" || ver == "12.0(29)S" || ver == "12.0(29)S1" || ver == "12.0(30)S" || ver == "12.0(30)S1" || ver == "12.0(30)S2" || ver == "12.0(30)S2a" || ver == "12.0(30)S2m" || ver == "12.0(30)S2n" || ver == "12.0(30)S3" || ver == "12.0(30)S3a" || ver == "12.0(30)S3b" || ver == "12.0(30)S3c" || ver == "12.0(30)S3d" || ver == "12.0(30)S3s" || ver == "12.0(30)S3t" || ver == "12.0(30)S4" || ver == "12.0(30)S4a" || ver == "12.0(30)S4b" || ver == "12.0(30)S5" || ver == "12.0(30)S5a" || ver == "12.0(31)S" || ver == "12.0(31)S0a" || ver == "12.0(31)S0b" || ver == "12.0(31)S1" || ver == "12.0(31)S1a" || ver == "12.0(31)S1b" || ver == "12.0(31)S1c" || ver == "12.0(31)S1d" || ver == "12.0(31)S1e" || ver == "12.0(31)S2" || ver == "12.0(31)S2a" || ver == "12.0(31)S2b" || ver == "12.0(31)S2c" || ver == "12.0(31)S2d" || ver == "12.0(31)S2s" || ver == "12.0(31)S2t" || ver == "12.0(31)S2u" || ver == "12.0(31)S2v" || ver == "12.0(31)S2w" || ver == "12.0(31)S2x" || ver == "12.0(31)S2y" || ver == "12.0(31)S2z" || ver == "12.0(31)S3" || ver == "12.0(31)S3a" || ver == "12.0(31)S3b" || ver == "12.0(31)S3c" || ver == "12.0(31)S3d" || ver == "12.0(31)S3e" || ver == "12.0(31)S4" || ver == "12.0(31)S4a" || ver == "12.0(31)S4b" || ver == "12.0(31)S4c" || ver == "12.0(31)S5" || ver == "12.0(31)S5a" || ver == "12.0(31)S5b" || ver == "12.0(31)S5c" || ver == "12.0(31)S5d" || ver == "12.0(31)S5e" || ver == "12.0(31)S6" || ver == "12.0(31)S6a" || ver == "12.0(31)S6b" || ver == "12.0(31)S6c" || ver == "12.0(31)S6d" || ver == "12.0(31)S6e" || ver == "12.0(31a)S2a" || ver == "12.0(31a)S2b" || ver == "12.0(32)S" || ver == "12.0(32)S1" || ver == "12.0(32)S1a" || ver == "12.0(32)S1b" || ver == "12.0(32)S10" || ver == "12.0(32)S11" || ver == "12.0(32)S11n" || ver == "12.0(32)S11o" || ver == "12.0(32)S11p" || ver == "12.0(32)S11q" || ver == "12.0(32)S11r" || ver == "12.0(32)S11v" || ver == "12.0(32)S11w" || ver == "12.0(32)S12" || ver == "12.0(32)S13" || ver == "12.0(32)S14" || ver == "12.0(32)S15" || ver == "12.0(32)S2" || ver == "12.0(32)S3" || ver == "12.0(32)S3a" || ver == "12.0(32)S3b" || ver == "12.0(32)S3c" || ver == "12.0(32)S3e" || ver == "12.0(32)S3f" || ver == "12.0(32)S4" || ver == "12.0(32)S4a" || ver == "12.0(32)S4b" || ver == "12.0(32)S5" || ver == "12.0(32)S5a" || ver == "12.0(32)S5b" || ver == "12.0(32)S6" || ver == "12.0(32)S6a" || ver == "12.0(32)S6b" || ver == "12.0(32)S6c" || ver == "12.0(32)S6ca" || ver == "12.0(32)S6d" || ver == "12.0(32)S6m" || ver == "12.0(32)S6n" || ver == "12.0(32)S6o" || ver == "12.0(32)S6p" || ver == "12.0(32)S6q" || ver == "12.0(32)S6r" || ver == "12.0(32)S7" || ver == "12.0(32)S8" || ver == "12.0(32)S9" || ver == "12.0(32c)S6b" || ver == "12.0(33)S" || ver == "12.0(33)S1" || ver == "12.0(33)S10" || ver == "12.0(33)S11" || ver == "12.0(33)S12" || ver == "12.0(33)S2" || ver == "12.0(33)S3" || ver == "12.0(33)S4" || ver == "12.0(33)S5" || ver == "12.0(33)S6" || ver == "12.0(33)S7" || ver == "12.0(33)S8" || ver == "12.0(33)S9")
  fixed_ver = "12.0(33)S13";
#12.0SV
else if (ver == "12.0(27)SV" || ver == "12.0(27)SV1" || ver == "12.0(27)SV2" || ver == "12.0(27)SV3" || ver == "12.0(27)SV4" || ver == "12.0(28)SV" || ver == "12.0(30)SV1" || ver == "12.0(31)SV" || ver == "12.0(31)SV1" || ver == "12.0(31)SV2")
  fixed_ver = "Refer to the vendor.";
#12.0SX
else if (ver == "12.0(30)SX")
  fixed_ver = "Refer to the vendor.";
#12.0SY
else if (ver == "12.0(27)SY" || ver == "12.0(32)SY" || ver == "12.0(32)SY0a" || ver == "12.0(32)SY0b" || ver == "12.0(32)SY0c" || ver == "12.0(32)SY0d" || ver == "12.0(32)SY0e" || ver == "12.0(32)SY0f" || ver == "12.0(32)SY0g" || ver == "12.0(32)SY0h" || ver == "12.0(32)SY0i" || ver == "12.0(32)SY0j" || ver == "12.0(32)SY1" || ver == "12.0(32)SY1a" || ver == "12.0(32)SY1b" || ver == "12.0(32)SY1c" || ver == "12.0(32)SY10" || ver == "12.0(32)SY11" || ver == "12.0(32)SY12" || ver == "12.0(32)SY12a" || ver == "12.0(32)SY13" || ver == "12.0(32)SY14" || ver == "12.0(32)SY15" || ver == "12.0(32)SY16" || ver == "12.0(32)SY17" || ver == "12.0(32)SY2" || ver == "12.0(32)SY2a" || ver == "12.0(32)SY2b" || ver == "12.0(32)SY2c" || ver == "12.0(32)SY2d" || ver == "12.0(32)SY2e" || ver == "12.0(32)SY2f" || ver == "12.0(32)SY2g" || ver == "12.0(32)SY2h" || ver == "12.0(32)SY2i" || ver == "12.0(32)SY3" || ver == "12.0(32)SY3a" || ver == "12.0(32)SY3b" || ver == "12.0(32)SY3c" || ver == "12.0(32)SY4" || ver == "12.0(32)SY4a" || ver == "12.0(32)SY4b" || ver == "12.0(32)SY4c" || ver == "12.0(32)SY4d" || ver == "12.0(32)SY5" || ver == "12.0(32)SY5a" || ver == "12.0(32)SY6" || ver == "12.0(32)SY6a" || ver == "12.0(32)SY6b" || ver == "12.0(32)SY6c" || ver == "12.0(32)SY6d" || ver == "12.0(32)SY6e" || ver == "12.0(32)SY6f" || ver == "12.0(32)SY7" || ver == "12.0(32)SY8" || ver == "12.0(32)SY8a" || ver == "12.0(32)SY8b" || ver == "12.0(32)SY9" || ver == "12.0(32)SY9a" || ver == "12.0(32)SY9b")
  fixed_ver = "Refer to the vendor.";
#12.0SYA
else if (ver == "12.0(32)SYA")
  fixed_ver = "Refer to the vendor.";
#12.0SZ
else if (ver == "12.0(27)SZ" || ver == "12.0(30)SZ" || ver == "12.0(30)SZ1" || ver == "12.0(30)SZ10" || ver == "12.0(30)SZ11" || ver == "12.0(30)SZ2" || ver == "12.0(30)SZ3" || ver == "12.0(30)SZ4" || ver == "12.0(30)SZ5" || ver == "12.0(30)SZ6" || ver == "12.0(30)SZ7" || ver == "12.0(30)SZ8" || ver == "12.0(30)SZ9" || ver == "12.0(31)SZ2")
  fixed_ver = "Refer to the vendor.";
#12.2EX
else if (ver == "12.2(58)EX")
  fixed_ver = "12.2(40)SE1, 12.2(46)SE1, 12.2(50)SE6, 12.2(52)SE1, 12.2(53)SE1, or 12.2(55)SE9";
#12.2EY
else if (ver == "12.2(52)EY" || ver == "12.2(52)EY1" || ver == "12.2(52)EY1c" || ver == "12.2(52)EY2" || ver == "12.2(52)EY2a" || ver == "12.2(52)EY3a" || ver == "12.2(52)EY4")
  fixed_ver = "12.2(53)EY";
#12.2EZ
else if (ver == "12.2(58)EZ" || ver == "12.2(60)EZ4")
  fixed_ver = "12.2(25)SEC";
#12.2IRA
else if (ver == "12.2(33)IRA")
  fixed_ver = "Refer to the vendor.";
#12.2IRB
else if (ver == "12.2(33)IRB")
  fixed_ver = "Refer to the vendor.";
#12.2IRC
else if (ver == "12.2(33)IRC")
  fixed_ver = "12.2(33)IRD1";
#12.2IRD
else if (ver == "12.2(33)IRD")
  fixed_ver = "12.2(33)IRD1";
#12.2IRE
else if (ver == "12.2(33)IRE" || ver == "12.2(33)IRE1" || ver == "12.2(33)IRE2")
  fixed_ver = "12.2(33)IRE3";
#12.2IRF
else if (ver == "12.2(33)IRF")
  fixed_ver = "Refer to the vendor.";
#12.2IRG
else if (ver == "12.2(33)IRG" || ver == "12.2(33)IRG1")
  fixed_ver = "Refer to the vendor.";
#12.2IRH
else if (ver == "12.2(33)IRH" || ver == "12.2(33)IRH1")
  fixed_ver = "Refer to the vendor.";
#12.2IRI
else if (ver == "12.2(33)IRI")
  fixed_ver = "Refer to the vendor.";
#12.2MRA
else if (ver == "12.2(33)MRA")
  fixed_ver = "12.2(33)SRE10";
#12.2MRB
else if (ver == "12.2(33)MRB" || ver == "12.2(33)MRB1" || ver == "12.2(33)MRB2" || ver == "12.2(33)MRB3" || ver == "12.2(33)MRB4" || ver == "12.2(33)MRB5" || ver == "12.2(33)MRB6")
  fixed_ver = "Refer to the vendor.";
#12.2SB
else if (ver == "12.2(33)SB" || ver == "12.2(33)SB1" || ver == "12.2(33)SB1a" || ver == "12.2(33)SB1b" || ver == "12.2(33)SB10" || ver == "12.2(33)SB11" || ver == "12.2(33)SB12" || ver == "12.2(33)SB13" || ver == "12.2(33)SB14" || ver == "12.2(33)SB15" || ver == "12.2(33)SB2" || ver == "12.2(33)SB3" || ver == "12.2(33)SB4" || ver == "12.2(33)SB5" || ver == "12.2(33)SB6" || ver == "12.2(33)SB6a" || ver == "12.2(33)SB6aa" || ver == "12.2(33)SB6b" || ver == "12.2(33)SB7" || ver == "12.2(33)SB8" || ver == "12.2(33)SB8b" || ver == "12.2(33)SB8c" || ver == "12.2(33)SB8d" || ver == "12.2(33)SB8e" || ver == "12.2(33)SB8f" || ver == "12.2(33)SB8g" || ver == "12.2(33)SB9" || ver == "12.2(34)SB1" || ver == "12.2(34)SB2" || ver == "12.2(34)SB3" || ver == "12.2(34)SB4" || ver == "12.2(34)SB4a" || ver == "12.2(34)SB4b" || ver == "12.2(34)SB4c" || ver == "12.2(34)SB4d")
  fixed_ver = "12.2(33)SB16";
#12.2SCA
else if (ver == "12.2(33)SCA" || ver == "12.2(33)SCA1" || ver == "12.2(33)SCA2")
  fixed_ver = "12.2(33)SCG7";
#12.2SCB
else if (ver == "12.2(33)SCB" || ver == "12.2(33)SCB1" || ver == "12.2(33)SCB10" || ver == "12.2(33)SCB11" || ver == "12.2(33)SCB2" || ver == "12.2(33)SCB3" || ver == "12.2(33)SCB4" || ver == "12.2(33)SCB5" || ver == "12.2(33)SCB6" || ver == "12.2(33)SCB7" || ver == "12.2(33)SCB8" || ver == "12.2(33)SCB9")
  fixed_ver = "12.2(33)SCG7";
#12.2SCC
else if (ver == "12.2(33)SCC" || ver == "12.2(33)SCC1" || ver == "12.2(33)SCC2" || ver == "12.2(33)SCC3" || ver == "12.2(33)SCC4" || ver == "12.2(33)SCC5" || ver == "12.2(33)SCC6" || ver == "12.2(33)SCC7")
  fixed_ver = "12.2(33)SCG7";
#12.2SCD
else if (ver == "12.2(33)SCD" || ver == "12.2(33)SCD1" || ver == "12.2(33)SCD2" || ver == "12.2(33)SCD3" || ver == "12.2(33)SCD4" || ver == "12.2(33)SCD5" || ver == "12.2(33)SCD6" || ver == "12.2(33)SCD7" || ver == "12.2(33)SCD8")
  fixed_ver = "12.2(33)SCG7";
#12.2SCE
else if (ver == "12.2(33)SCE" || ver == "12.2(33)SCE1" || ver == "12.2(33)SCE2" || ver == "12.2(33)SCE3" || ver == "12.2(33)SCE4" || ver == "12.2(33)SCE5" || ver == "12.2(33)SCE6")
  fixed_ver = "12.2(33)SCG7";
#12.2SCF
else if (ver == "12.2(33)SCF" || ver == "12.2(33)SCF1" || ver == "12.2(33)SCF2" || ver == "12.2(33)SCF3" || ver == "12.2(33)SCF4" || ver == "12.2(33)SCF5")
  fixed_ver = "12.2(33)SCG7";
#12.2SCG
else if (ver == "12.2(33)SCG" || ver == "12.2(33)SCG1" || ver == "12.2(33)SCG2" || ver == "12.2(33)SCG3" || ver == "12.2(33)SCG4" || ver == "12.2(33)SCG5" || ver == "12.2(33)SCG6")
  fixed_ver = "12.2(33)SCG7";
#12.2SCH
else if (ver == "12.2(33)SCH" || ver == "12.2(33)SCH0a" || ver == "12.2(33)SCH1")
  fixed_ver = "12.2(33)SCH2";
#12.2SE
else if (ver == "12.2(40)SE" || ver == "12.2(44)SE" || ver == "12.2(44)SE1" || ver == "12.2(44)SE2" || ver == "12.2(44)SE3" || ver == "12.2(44)SE5" || ver == "12.2(44)SE6" || ver == "12.2(46)SE" || ver == "12.2(50)SE" || ver == "12.2(50)SE1" || ver == "12.2(50)SE3" || ver == "12.2(50)SE4" || ver == "12.2(50)SE5" || ver == "12.2(52)SE" || ver == "12.2(54)SE" || ver == "12.2(55)SE" || ver == "12.2(55)SE3" || ver == "12.2(55)SE4" || ver == "12.2(55)SE5" || ver == "12.2(55)SE6" || ver == "12.2(55)SE7" || ver == "12.2(55)SE8" || ver == "12.2(58)SE2")
  fixed_ver = "12.2(40)SE1, 12.2(46)SE1, 12.2(50)SE6, 12.2(52)SE1, 12.2(53)SE1, or 12.2(55)SE9";
#12.2SRA
else if (ver == "12.2(33)SRA" || ver == "12.2(33)SRA1" || ver == "12.2(33)SRA2" || ver == "12.2(33)SRA3" || ver == "12.2(33)SRA4" || ver == "12.2(33)SRA5" || ver == "12.2(33)SRA6" || ver == "12.2(33)SRA7")
  fixed_ver = "12.2(33)SRE10";
#12.2SRB
else if (ver == "12.2(33)SRB" || ver == "12.2(33)SRB1" || ver == "12.2(33)SRB2" || ver == "12.2(33)SRB3" || ver == "12.2(33)SRB4" || ver == "12.2(33)SRB5" || ver == "12.2(33)SRB5a" || ver == "12.2(33)SRB6" || ver == "12.2(33)SRB7")
  fixed_ver = "12.2(33)SRE10";
#12.2SRC
else if (ver == "12.2(33)SRC" || ver == "12.2(33)SRC1" || ver == "12.2(33)SRC2" || ver == "12.2(33)SRC3" || ver == "12.2(33)SRC4" || ver == "12.2(33)SRC5" || ver == "12.2(33)SRC6")
  fixed_ver = "12.2(33)SRE10";
#12.2SRD
else if (ver == "12.2(33)SRD" || ver == "12.2(33)SRD1" || ver == "12.2(33)SRD2" || ver == "12.2(33)SRD2a" || ver == "12.2(33)SRD3" || ver == "12.2(33)SRD4" || ver == "12.2(33)SRD4a" || ver == "12.2(33)SRD5" || ver == "12.2(33)SRD6" || ver == "12.2(33)SRD7" || ver == "12.2(33)SRD8")
  fixed_ver = "12.2(33)SRE10";
#12.2SRE
else if (ver == "12.2(33)SRE" || ver == "12.2(33)SRE0a" || ver == "12.2(33)SRE1" || ver == "12.2(33)SRE2" || ver == "12.2(33)SRE3" || ver == "12.2(33)SRE4" || ver == "12.2(33)SRE5" || ver == "12.2(33)SRE6" || ver == "12.2(33)SRE7" || ver == "12.2(33)SRE7a" || ver == "12.2(33)SRE8" || ver == "12.2(33)SRE9" || ver == "12.2(33)SRE9a")
  fixed_ver = "12.2(33)SRE10";
#12.2SXH
else if (ver == "12.2(33)SXH" || ver == "12.2(33)SXH0a" || ver == "12.2(33)SXH1" || ver == "12.2(33)SXH2" || ver == "12.2(33)SXH2a" || ver == "12.2(33)SXH3" || ver == "12.2(33)SXH3a" || ver == "12.2(33)SXH4" || ver == "12.2(33)SXH5" || ver == "12.2(33)SXH6" || ver == "12.2(33)SXH7" || ver == "12.2(33)SXH7v" || ver == "12.2(33)SXH7w" || ver == "12.2(33)SXH8" || ver == "12.2(33)SXH8a" || ver == "12.2(33)SXH8b")
  fixed_ver = "12.2(33)SXH7x";
#12.2SXI
else if (ver == "12.2(33)SXI" || ver == "12.2(33)SXI1" || ver == "12.2(33)SXI10" || ver == "12.2(33)SXI11" || ver == "12.2(33)SXI12" || ver == "12.2(33)SXI2" || ver == "12.2(33)SXI2a" || ver == "12.2(33)SXI3" || ver == "12.2(33)SXI3a" || ver == "12.2(33)SXI3z" || ver == "12.2(33)SXI4" || ver == "12.2(33)SXI4a" || ver == "12.2(33)SXI5" || ver == "12.2(33)SXI5a" || ver == "12.2(33)SXI6" || ver == "12.2(33)SXI7" || ver == "12.2(33)SXI8" || ver == "12.2(33)SXI8a" || ver == "12.2(33)SXI9" || ver == "12.2(33)SXI9a")
  fixed_ver = "12.2(33)SXI4b or 12.2(33)SXI13";
#12.2SXJ
else if (ver == "12.2(33)SXJ" || ver == "12.2(33)SXJ1" || ver == "12.2(33)SXJ2" || ver == "12.2(33)SXJ3" || ver == "12.2(33)SXJ4" || ver == "12.2(33)SXJ5" || ver == "12.2(33)SXJ6")
  fixed_ver = "12.2(33)SXJ7";
#12.2SY
else if (ver == "12.2(50)SY" || ver == "12.2(50)SY1" || ver == "12.2(50)SY2" || ver == "12.2(50)SY3" || ver == "12.2(50)SY4")
  fixed_ver = "Refer to the vendor.";
#12.2XN
else if (ver == "12.2(33)XN" || ver == "12.2(33)XN1")
  fixed_ver = "Refer to the vendor.";
#12.2ZI
else if (ver == "12.2(33)ZI")
  fixed_ver = "Refer to the vendor.";
#12.2ZW
else if (ver == "12.2(33)ZW")
  fixed_ver = "Refer to the vendor.";
#12.2ZZ
else if (ver == "12.2(33)ZZ")
  fixed_ver = "Refer to the vendor.";
#12.4GC
else if (ver == "12.4(22)GC1" || ver == "12.4(22)GC1a" || ver == "12.4(24)GC1" || ver == "12.4(24)GC3" || ver == "12.4(24)GC3a" || ver == "12.4(24)GC4" || ver == "12.4(24)GC5")
  fixed_ver = "Refer to the vendor.";
#12.4MD
else if (ver == "12.4(15)MD" || ver == "12.4(15)MD1" || ver == "12.4(15)MD2" || ver == "12.4(15)MD3" || ver == "12.4(15)MD4" || ver == "12.4(15)MD5" || ver == "12.4(22)MD" || ver == "12.4(22)MD1" || ver == "12.4(22)MD2" || ver == "12.4(24)MD" || ver == "12.4(24)MD1" || ver == "12.4(24)MD2" || ver == "12.4(24)MD3" || ver == "12.4(24)MD4" || ver == "12.4(24)MD5" || ver == "12.4(24)MD6" || ver == "12.4(24)MD7")
  fixed_ver = "12.4(24)MDB17";
#12.4MDA
else if (ver == "12.4(22)MDA" || ver == "12.4(22)MDA1" || ver == "12.4(22)MDA2" || ver == "12.4(22)MDA3" || ver == "12.4(22)MDA4" || ver == "12.4(22)MDA5" || ver == "12.4(22)MDA6" || ver == "12.4(24)MDA" || ver == "12.4(24)MDA1" || ver == "12.4(24)MDA10" || ver == "12.4(24)MDA11" || ver == "12.4(24)MDA12" || ver == "12.4(24)MDA13" || ver == "12.4(24)MDA2" || ver == "12.4(24)MDA3" || ver == "12.4(24)MDA4" || ver == "12.4(24)MDA5" || ver == "12.4(24)MDA6" || ver == "12.4(24)MDA7" || ver == "12.4(24)MDA8" || ver == "12.4(24)MDA9")
  fixed_ver = "12.4(24)MDB17";
#12.4MDB
else if (ver == "12.4(24)MDB" || ver == "12.4(24)MDB1" || ver == "12.4(24)MDB10" || ver == "12.4(24)MDB11" || ver == "12.4(24)MDB12" || ver == "12.4(24)MDB13" || ver == "12.4(24)MDB14" || ver == "12.4(24)MDB15" || ver == "12.4(24)MDB16" || ver == "12.4(24)MDB3" || ver == "12.4(24)MDB4" || ver == "12.4(24)MDB5" || ver == "12.4(24)MDB5a" || ver == "12.4(24)MDB6" || ver == "12.4(24)MDB7" || ver == "12.4(24)MDB8" || ver == "12.4(24)MDB9")
  fixed_ver = "12.4(24)MDB17";
#12.4MR
else if (ver == "12.4(19)MR" || ver == "12.4(19)MR1" || ver == "12.4(19)MR2" || ver == "12.4(19)MR3" || ver == "12.4(20)MR" || ver == "12.4(20)MR2")
  fixed_ver = "Refer to the vendor.";
#12.4MRA
else if (ver == "12.4(20)MRA" || ver == "12.4(20)MRA1")
  fixed_ver = "Refer to the vendor.";
#12.4MRB
else if (ver == "12.4(20)MRB" || ver == "12.4(20)MRB1")
  fixed_ver = "12.4(24)T11";
#12.4T
else if (ver == "12.4(20)T" || ver == "12.4(20)T1" || ver == "12.4(20)T2" || ver == "12.4(20)T3" || ver == "12.4(20)T4" || ver == "12.4(20)T5" || ver == "12.4(20)T5a" || ver == "12.4(20)T6" || ver == "12.4(22)T" || ver == "12.4(22)T1" || ver == "12.4(22)T2" || ver == "12.4(22)T3" || ver == "12.4(22)T4" || ver == "12.4(22)T5" || ver == "12.4(24)T" || ver == "12.4(24)T1" || ver == "12.4(24)T10" || ver == "12.4(24)T2" || ver == "12.4(24)T3" || ver == "12.4(24)T3c" || ver == "12.4(24)T3e" || ver == "12.4(24)T3f" || ver == "12.4(24)T31f" || ver == "12.4(24)T3g" || ver == "12.4(24)T32f" || ver == "12.4(24)T33f" || ver == "12.4(24)T34f" || ver == "12.4(24)T35c" || ver == "12.4(24)T35f" || ver == "12.4(24)T4" || ver == "12.4(24)T4a" || ver == "12.4(24)T4b" || ver == "12.4(24)T4c" || ver == "12.4(24)T4d" || ver == "12.4(24)T4e" || ver == "12.4(24)T4f" || ver == "12.4(24)T4g" || ver == "12.4(24)T4h" || ver == "12.4(24)T4i" || ver == "12.4(24)T4j" || ver == "12.4(24)T4k" || ver == "12.4(24)T4l" || ver == "12.4(24)T4m" || ver == "12.4(24)T4n" || ver == "12.4(24)T4o" || ver == "12.4(24)T5" || ver == "12.4(24)T6" || ver == "12.4(24)T7" || ver == "12.4(24)T8" || ver == "12.4(24)T9")
  fixed_ver = "12.4(24)T11";
#12.4XQ
else if (ver == "12.4(15)XQ" || ver == "12.4(15)XQ1" || ver == "12.4(15)XQ2" || ver == "12.4(15)XQ2a" || ver == "12.4(15)XQ2b" || ver == "12.4(15)XQ2c" || ver == "12.4(15)XQ2d" || ver == "12.4(15)XQ3" || ver == "12.4(15)XQ4" || ver == "12.4(15)XQ5" || ver == "12.4(15)XQ6" || ver == "12.4(15)XQ7" || ver == "12.4(15)XQ8")
  fixed_ver = "12.4(24)T11";
#12.4XR
else if (ver == "12.4(15)XR" || ver == "12.4(15)XR1" || ver == "12.4(15)XR10" || ver == "12.4(15)XR2" || ver == "12.4(15)XR3" || ver == "12.4(15)XR4" || ver == "12.4(15)XR5" || ver == "12.4(15)XR6" || ver == "12.4(15)XR7" || ver == "12.4(15)XR8" || ver == "12.4(15)XR9" || ver == "12.4(22)XR" || ver == "12.4(22)XR1" || ver == "12.4(22)XR10" || ver == "12.4(22)XR11" || ver == "12.4(22)XR12" || ver == "12.4(22)XR2" || ver == "12.4(22)XR3" || ver == "12.4(22)XR4" || ver == "12.4(22)XR5" || ver == "12.4(22)XR6" || ver == "12.4(22)XR7" || ver == "12.4(22)XR8" || ver == "12.4(22)XR9")
  fixed_ver = "12.4(24)T11";
#12.4XY
else if (ver == "12.4(15)XY" || ver == "12.4(15)XY1" || ver == "12.4(15)XY2" || ver == "12.4(15)XY3" || ver == "12.4(15)XY4" || ver == "12.4(15)XY5")
  fixed_ver = "12.4(15)XY5";
#12.4XZ
else if (ver == "12.4(15)XZ" || ver == "12.4(15)XZ1" || ver == "12.4(15)XZ2")
  fixed_ver = "12.4(24)T11";
#12.4YA
else if (ver == "12.4(20)YA" || ver == "12.4(20)YA1" || ver == "12.4(20)YA2" || ver == "12.4(20)YA3")
  fixed_ver = "12.4(24)T11";
#12.4YB
else if (ver == "12.4(22)YB" || ver == "12.4(22)YB1" || ver == "12.4(22)YB2" || ver == "12.4(22)YB3" || ver == "12.4(22)YB4" || ver == "12.4(22)YB5" || ver == "12.4(22)YB6" || ver == "12.4(22)YB7" || ver == "12.4(22)YB8")
  fixed_ver = "Refer to the vendor.";
#12.4YD
else if (ver == "12.4(22)YD" || ver == "12.4(22)YD1" || ver == "12.4(22)YD2" || ver == "12.4(22)YD3" || ver == "12.4(22)YD4")
  fixed_ver = "Refer to the vendor.";
#12.4YE
else if (ver == "12.4(22)YE" || ver == "12.4(22)YE1" || ver == "12.4(22)YE2" || ver == "12.4(22)YE3" || ver == "12.4(22)YE4" || ver == "12.4(22)YE5" || ver == "12.4(22)YE6" || ver == "12.4(24)YE" || ver == "12.4(24)YE1" || ver == "12.4(24)YE2" || ver == "12.4(24)YE3" || ver == "12.4(24)YE3a" || ver == "12.4(24)YE3b" || ver == "12.4(24)YE3c" || ver == "12.4(24)YE3d" || ver == "12.4(24)YE3e" || ver == "12.4(24)YE4" || ver == "12.4(24)YE5" || ver == "12.4(24)YE6" || ver == "12.4(24)YE7")
  fixed_ver = "12.4(24)T11";
#12.4YG
else if (ver == "12.4(24)YG1" || ver == "12.4(24)YG2" || ver == "12.4(24)YG3" || ver == "12.4(24)YG4")
  fixed_ver = "Refer to the vendor.";
#12.4YS
else if (ver == "12.4(24)YS" || ver == "12.4(24)YS1" || ver == "12.4(24)YS2" || ver == "12.4(24)YS3" || ver == "12.4(24)YS4" || ver == "12.4(24)YS5")
  fixed_ver = "12.4(24)YS6";
#15.0EJ
else if (ver == "15.0(2)EJ")
  fixed_ver = "15.0(2)EJ1";
#15.0EX
else if (ver == "15.0(1)EX")
  fixed_ver = "15.0(1)EX1 or 15.0(2)EX";
#15.0EZ
else if (ver == "15.0(1)EZ" || ver == "15.0(2)EZ")
  fixed_ver = "15.0(1)EZ1";
#15.0M
else if (ver == "15.0(1)M" || ver == "15.0(1)M1" || ver == "15.0(1)M10" || ver == "15.0(1)M2" || ver == "15.0(1)M3" || ver == "15.0(1)M4" || ver == "15.0(1)M5" || ver == "15.0(1)M6" || ver == "15.0(1)M6a" || ver == "15.0(1)M7" || ver == "15.0(1)M8" || ver == "15.0(1)M9")
  fixed_ver = "15.1(4)M8";
#15.0MR
else if (ver == "15.0(1)MR" || ver == "15.0(2)MR")
  fixed_ver = "15.1(3)S7";
#15.0S
else if (ver == "15.0(1)S" || ver == "15.0(1)S1" || ver == "15.0(1)S2" || ver == "15.0(1)S3a" || ver == "15.0(1)S4" || ver == "15.0(1)S4a" || ver == "15.0(1)S5" || ver == "15.0(1)S6")
  fixed_ver = "15.1(3)S7";
#15.0SE
else if (ver == "15.0(1)SE" || ver == "15.0(1)SE1" || ver == "15.0(1)SE2" || ver == "15.0(1)SE3" || ver == "15.0(2)SE" || ver == "15.0(2)SE1" || ver == "15.0(2)SE2" || ver == "15.0(2)SE3" || ver == "15.0(2)SE4" || ver == "15.0(2)SE5")
  fixed_ver = "15.0(2)SE6";
#15.0SY
else if (ver == "15.0(1)SY" || ver == "15.0(1)SY1" || ver == "15.0(1)SY2" || ver == "15.0(1)SY3" || ver == "15.0(1)SY4" || ver == "15.0(1)SY5" || ver == "15.0(1)SY6")
  fixed_ver = "15.0(1)SY7";
#15.0XA
else if (ver == "15.0(1)XA" || ver == "15.0(1)XA1" || ver == "15.0(1)XA2" || ver == "15.0(1)XA3" || ver == "15.0(1)XA4" || ver == "15.0(1)XA5")
  fixed_ver = "15.1(4)M8";
#15.1EY
else if (ver == "15.1(2)EY" || ver == "15.1(2)EY1" || ver == "15.1(2)EY1a" || ver == "15.1(2)EY2" || ver == "15.1(2)EY2a" || ver == "15.1(2)EY3" || ver == "15.1(2)EY4")
  fixed_ver = "15.2(4)S1c, 15.2(4)S2t, or 15.2(4)S4";
#15.1GC
else if (ver == "15.1(2)GC" || ver == "15.1(2)GC1" || ver == "15.1(2)GC2" || ver == "15.1(4)GC" || ver == "15.1(4)GC1")
  fixed_ver = "15.1(4)GC2";
#15.1M
else if (ver == "15.1(4)M" || ver == "15.1(4)M0a" || ver == "15.1(4)M0b" || ver == "15.1(4)M1" || ver == "15.1(4)M2" || ver == "15.1(4)M3" || ver == "15.1(4)M3a" || ver == "15.1(4)M4" || ver == "15.1(4)M5" || ver == "15.1(4)M6" || ver == "15.1(4)M7")
  fixed_ver = "15.1(4)M8";
#15.1MR
else if (ver == "15.1(1)MR" || ver == "15.1(1)MR1" || ver == "15.1(1)MR2" || ver == "15.1(1)MR3" || ver == "15.1(1)MR4" || ver == "15.1(1)MR5" || ver == "15.1(1)MR6" || ver == "15.1(3)MR")
  fixed_ver = "Refer to the vendor.";
#15.1MRA
else if (ver == "15.1(3)MRA" || ver == "15.1(3)MRA1" || ver == "15.1(3)MRA2")
  fixed_ver = "15.1(3)MRA3";
#15.1S
else if (ver == "15.1(1)S" || ver == "15.1(1)S1" || ver == "15.1(1)S2" || ver == "15.1(2)S" || ver == "15.1(2)S1" || ver == "15.1(2)S2" || ver == "15.1(3)S" || ver == "15.1(3)S0a" || ver == "15.1(3)S1" || ver == "15.1(3)S2" || ver == "15.1(3)S3" || ver == "15.1(3)S4" || ver == "15.1(3)S5" || ver == "15.1(3)S5a" || ver == "15.1(3)S6")
  fixed_ver = "15.1(3)S7";
#15.1SA
else if (ver == "15.1(1)SA" || ver == "15.1(1)SA1" || ver == "15.1(1)SA2")
  fixed_ver = "Refer to the vendor.";
#15.1SG
else if (ver == "15.1(1)SG" || ver == "15.1(1)SG1" || ver == "15.1(1)SG2" || ver == "15.1(2)SG" || ver == "15.1(2)SG1" || ver == "15.1(2)SG2" || ver == "15.1(2)SG3")
  fixed_ver = "15.1(2)SG4";
#15.1SNG
else if (ver == "15.1(2)SNG")
  fixed_ver = "Refer to the vendor.";
#15.1SNH
else if (ver == "15.1(2)SNH" || ver == "15.1(2)SNH1")
  fixed_ver = "Refer to the vendor.";
#15.1SNI
else if (ver == "15.1(2)SNI" || ver == "15.1(2)SNI1")
  fixed_ver = "Refer to the vendor.";
#15.1SVG
else if (ver == "15.1(3)SVG2" || ver == "15.1(3)SVG3")
  fixed_ver = "Refer to the vendor.";
#15.1SVH
else if (ver == "15.1(3)SVH")
  fixed_ver = "Refer to the vendor.";
#15.1SY
else if (ver == "15.1(1)SY" || ver == "15.1(1)SY1" || ver == "15.1(2)SY")
  fixed_ver = "15.1(1)SY2 or 15.1(2)SY1";
#15.1T
else if (ver == "15.1(1)T" || ver == "15.1(1)T1" || ver == "15.1(1)T2" || ver == "15.1(1)T3" || ver == "15.1(1)T4" || ver == "15.1(1)T5" || ver == "15.1(2)T" || ver == "15.1(2)T0a" || ver == "15.1(2)T1" || ver == "15.1(2)T2" || ver == "15.1(2)T2a" || ver == "15.1(2)T3" || ver == "15.1(2)T4" || ver == "15.1(2)T5" || ver == "15.1(3)T" || ver == "15.1(3)T1" || ver == "15.1(3)T2" || ver == "15.1(3)T3" || ver == "15.1(3)T4")
  fixed_ver = "15.1(4)M8";
#15.1XB
else if (ver == "15.1(1)XB" || ver == "15.1(1)XB1" || ver == "15.1(1)XB2" || ver == "15.1(1)XB3" || ver == "15.1(4)XB4" || ver == "15.1(4)XB5" || ver == "15.1(4)XB5a" || ver == "15.1(4)XB6" || ver == "15.1(4)XB7" || ver == "15.1(4)XB8" || ver == "15.1(4)XB8a")
  fixed_ver = "15.1(4)M8";
#15.2GC
else if (ver == "15.2(1)GC" || ver == "15.2(1)GC1" || ver == "15.2(1)GC2" || ver == "15.2(2)GC" || ver == "15.2(3)GC" || ver == "15.2(3)GC1" || ver == "15.2(4)GC")
  fixed_ver = "15.2(4)GC1";
#15.2GCA
else if (ver == "15.2(3)GCA" || ver == "15.2(3)GCA1")
  fixed_ver = "15.4(1)T";
#15.2M
else if (ver == "15.2(4)M" || ver == "15.2(4)M1" || ver == "15.2(4)M2" || ver == "15.2(4)M3" || ver == "15.2(4)M4" || ver == "15.2(4)M5")
  fixed_ver = "15.2(4)M6";
#15.2S
else if (ver == "15.2(1)S" || ver == "15.2(1)S1" || ver == "15.2(1)S2" || ver == "15.2(2)S" || ver == "15.2(2)S0a" || ver == "15.2(2)S0c" || ver == "15.2(2)S0d" || ver == "15.2(2)S1" || ver == "15.2(2)S2" || ver == "15.2(4)S" || ver == "15.2(4)S0c" || ver == "15.2(4)S1" || ver == "15.2(4)S2" || ver == "15.2(4)S3" || ver == "15.2(4)S3a")
  fixed_ver = "15.2(4)S1c, 15.2(4)S2t, or 15.2(4)S4";
#15.2SB
else if (ver == "15.2(1)SB" || ver == "15.2(1)SB1" || ver == "15.2(1)SB3" || ver == "15.2(1)SB4")
  fixed_ver = "15.2(2)SB";
#15.2SC
else if (ver == "15.2(1)SC1a" || ver == "15.2(1)SC2" || ver == "15.2(2)SC")
  fixed_ver = "Refer to the vendor.";
#15.2SD
else if (ver == "15.2(1)SD1" || ver == "15.2(1)SD2" || ver == "15.2(1)SD3" || ver == "15.2(1)SD4" || ver == "15.2(1)SD6" || ver == "15.2(1)SD6a" || ver == "15.2(1)SD7")
  fixed_ver = "Refer to the vendor.";
#15.2SNG
else if (ver == "15.2(2)SNG")
  fixed_ver = "Refer to the vendor.";
#15.2SNH
else if (ver == "15.2(2)SNH" || ver == "15.2(2)SNH1")
  fixed_ver = "Refer to the vendor.";
#15.2SNI
else if (ver == "15.2(2)SNI")
  fixed_ver = "15.3(3)S1";
#15.2T
else if (ver == "15.2(1)T" || ver == "15.2(1)T1" || ver == "15.2(1)T2" || ver == "15.2(1)T3" || ver == "15.2(1)T3a" || ver == "15.2(1)T4" || ver == "15.2(2)T" || ver == "15.2(2)T1" || ver == "15.2(2)T2" || ver == "15.2(2)T3" || ver == "15.2(2)T4" || ver == "15.2(3)T" || ver == "15.2(3)T1" || ver == "15.2(3)T2" || ver == "15.2(3)T3" || ver == "15.2(3)T4")
  fixed_ver = "15.2(4)M6";
#15.2XA
else if (ver == "15.2(3)XA")
  fixed_ver = "";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "15.2(4)M6";
#15.3M
else if (ver == "15.3(3)M" || ver == "15.3(3)M1")
  fixed_ver = "15.3(3)M2";
#15.3S
else if (ver == "15.3(1)S" || ver == "15.3(1)S1" || ver == "15.3(1)S1e" || ver == "15.3(1)S2" || ver == "15.3(2)S" || ver == "15.3(2)S0a" || ver == "15.3(2)S0xa" || ver == "15.3(2)S1" || ver == "15.3(2)S1b" || ver == "15.3(2)S1c" || ver == "15.3(2)S2" || ver == "15.3(3)S" || ver == "15.3(3)S0b")
  fixed_ver = "15.3(3)S1";
#15.3T
else if (ver == "15.3(1)T" || ver == "15.3(1)T1" || ver == "15.3(1)T2" || ver == "15.3(1)T3" || ver == "15.3(2)T" || ver == "15.3(2)T1" || ver == "15.3(2)T2")
  fixed_ver = "15.3(1)T4 or 15.3(2)T3";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# RSVP check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*(?:ip rsvp bandwidth|mpls traffic-eng tunnel)", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because RSVP is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
