#TRUSTED 75d4451d021b6ba1cd16ea320b6d219591080bd1935ba76d2466858a03fce4fda50a603587bb057fa2d935427980c857c00f39b41102086b6d88d464d2b2ef07fbd0121c70045e1e1ad3dc1ab308a0d5011d289f1d5a68e57dda688973f1a01df2c9abf5ab431b7b7bcd8d380e5086e75e9938db088b3239439d06dba1293dc73d8dc98bb6e679b85837876c10560ffd942e056c5557fb5778dd532652cc4351d3db9229f40e3920753a4862b90331f72cf98dbdb3e329661e9187e4dc14caeb696f883eb5fa566a6ba1ea664e25ce5bf64a6f49d12ced559cd41464ee3074cdbc8669ab0f0e0147ac7b0e410e31b93bbfe1b9f83b70c7d6d299597b462c2537107b30486c2797a92c72ae4404bb4164585c7a1a44a5b607f9e6346a41d8dd59ec96cf50f42a2e3354db8249185b7bbd70793dd59104625b48be2728243de243e1ca4a53b473ea17d3a48a2ae0190b8df88ab7086c332bb3b135a0b168d8c221604f946a381e16be8b2e7ea42c66bf1ebeece3b3f9eeaf56705cc899e112493959aee56798ef8deb25401678377628c89bfb55f4f1dfb286652e7ac3b03bd08b13d4a87cf401608629162e715f595a4fe4c4909ddb4f0e8df9e92bf0e57110d44760e2e7b50e00e7a1fc4fa9e75f47b84eeb06701c330f36e9b4507768413364f5c8e8e815578a56b2227ae22e391690160958bc4468057f4ea6b288874ce161
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80102);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/12/18");

  script_name(english:"SSL Custom CA Setup");
  script_summary(english:"Setup the loading of cert authorities for validation.");

  script_set_attribute(attribute:"synopsis", value:"Configure the SSL certificates for validation of connections.");
  script_set_attribute(attribute:"description", value:
"Configure the loading of the certificate authorities for SSL
validation. This will load the Tenable-managed default certificate
authorities and allow Nessus users to load custom certificate
authorities.

Multiple custom CA files are available to help with the management of
custom certificate authorities. Custom certificate authority naming :

  - custom_CA.inc
  - custom_CA_0.inc
  - custom_CA_1.inc
  - custom_CA_2.inc
  - custom_CA_3.inc
  - custom_CA_4.inc
  - custom_CA_5.inc
  - custom_CA_6.inc
  - custom_CA_7.inc
  - custom_CA_8.inc
  - custom_CA_9.inc");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_INIT);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  exit(0);
}
include("global_settings.inc");
include("misc_func.inc");

set_kb_item(name:"SSL/CA_list", value:"known_CA.inc");

custom_ca = "custom_CA.inc";
if (file_stat(custom_ca) > 0)
  set_kb_item(name:"SSL/CA_list", value:custom_ca);

for (i=0; i<10; i++)
{
  custom_ca_addons = "custom_CA_"+i+".inc";
  if (file_stat(custom_ca_addons) > 0)
    set_kb_item(name:"SSL/CA_list", value:custom_ca_addons);
}
