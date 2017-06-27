#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201301-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(63402);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2007-1861", "CVE-2007-2437", "CVE-2007-2671", "CVE-2007-3073", "CVE-2008-0016", "CVE-2008-0017", "CVE-2008-0367", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069", "CVE-2008-4070", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5015", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024", "CVE-2008-5052", "CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5505", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513", "CVE-2008-5822", "CVE-2008-5913", "CVE-2008-6961", "CVE-2009-0071", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358", "CVE-2009-0652", "CVE-2009-0689", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777", "CVE-2009-1044", "CVE-2009-1169", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312", "CVE-2009-1313", "CVE-2009-1392", "CVE-2009-1571", "CVE-2009-1828", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841", "CVE-2009-2043", "CVE-2009-2044", "CVE-2009-2061", "CVE-2009-2065", "CVE-2009-2210", "CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464", "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2467", "CVE-2009-2469", "CVE-2009-2470", "CVE-2009-2471", "CVE-2009-2472", "CVE-2009-2477", "CVE-2009-2478", "CVE-2009-2479", "CVE-2009-2535", "CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2664", "CVE-2009-2665", "CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079", "CVE-2009-3274", "CVE-2009-3371", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3377", "CVE-2009-3378", "CVE-2009-3379", "CVE-2009-3380", "CVE-2009-3381", "CVE-2009-3382", "CVE-2009-3383", "CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3555", "CVE-2009-3978", "CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3981", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986", "CVE-2009-3987", "CVE-2009-3988", "CVE-2010-0159", "CVE-2010-0160", "CVE-2010-0162", "CVE-2010-0163", "CVE-2010-0164", "CVE-2010-0165", "CVE-2010-0166", "CVE-2010-0167", "CVE-2010-0168", "CVE-2010-0169", "CVE-2010-0170", "CVE-2010-0171", "CVE-2010-0172", "CVE-2010-0173", "CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178", "CVE-2010-0179", "CVE-2010-0181", "CVE-2010-0182", "CVE-2010-0183", "CVE-2010-0220", "CVE-2010-0648", "CVE-2010-0654", "CVE-2010-1028", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-1205", "CVE-2010-1206", "CVE-2010-1207", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1210", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-1214", "CVE-2010-1215", "CVE-2010-1585", "CVE-2010-2751", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754", "CVE-2010-2755", "CVE-2010-2760", "CVE-2010-2762", "CVE-2010-2763", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-2770", "CVE-2010-3131", "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169", "CVE-2010-3170", "CVE-2010-3171", "CVE-2010-3173", "CVE-2010-3174", "CVE-2010-3175", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3182", "CVE-2010-3183", "CVE-2010-3399", "CVE-2010-3400", "CVE-2010-3765", "CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3769", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3777", "CVE-2010-3778", "CVE-2010-4508", "CVE-2010-5074", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0061", "CVE-2011-0062", "CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0068", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0076", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0079", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-0082", "CVE-2011-0083", "CVE-2011-0084", "CVE-2011-0085", "CVE-2011-1187", "CVE-2011-1202", "CVE-2011-1712", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2369", "CVE-2011-2370", "CVE-2011-2371", "CVE-2011-2372", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2376", "CVE-2011-2377", "CVE-2011-2378", "CVE-2011-2605", "CVE-2011-2980", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984", "CVE-2011-2985", "CVE-2011-2986", "CVE-2011-2987", "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2990", "CVE-2011-2991", "CVE-2011-2993", "CVE-2011-2995", "CVE-2011-2996", "CVE-2011-2997", "CVE-2011-2998", "CVE-2011-2999", "CVE-2011-3000", "CVE-2011-3001", "CVE-2011-3002", "CVE-2011-3003", "CVE-2011-3004", "CVE-2011-3005", "CVE-2011-3026", "CVE-2011-3062", "CVE-2011-3101", "CVE-2011-3232", "CVE-2011-3389", "CVE-2011-3640", "CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3649", "CVE-2011-3650", "CVE-2011-3651", "CVE-2011-3652", "CVE-2011-3653", "CVE-2011-3654", "CVE-2011-3655", "CVE-2011-3658", "CVE-2011-3659", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665", "CVE-2011-3670", "CVE-2011-3866", "CVE-2011-4688", "CVE-2012-0441", "CVE-2012-0442", "CVE-2012-0443", "CVE-2012-0444", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0449", "CVE-2012-0450", "CVE-2012-0451", "CVE-2012-0452", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0463", "CVE-2012-0464", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0475", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479", "CVE-2012-1937", "CVE-2012-1938", "CVE-2012-1939", "CVE-2012-1940", "CVE-2012-1941", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947", "CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1956", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967", "CVE-2012-1970", "CVE-2012-1971", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-1994", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3965", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3971", "CVE-2012-3972", "CVE-2012-3973", "CVE-2012-3975", "CVE-2012-3976", "CVE-2012-3978", "CVE-2012-3980", "CVE-2012-3982", "CVE-2012-3984", "CVE-2012-3985", "CVE-2012-3986", "CVE-2012-3988", "CVE-2012-3989", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184", "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188", "CVE-2012-4190", "CVE-2012-4191", "CVE-2012-4192", "CVE-2012-4193", "CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196", "CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-4206", "CVE-2012-4207", "CVE-2012-4208", "CVE-2012-4209", "CVE-2012-4210", "CVE-2012-4212", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-4930", "CVE-2012-5354", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5836", "CVE-2012-5838", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842", "CVE-2012-5843");
  script_bugtraq_id(51752, 51753, 51754, 51756, 51757, 51765, 51787, 51975, 52456, 52457, 52458, 52459, 52460, 52461, 52463, 52464, 52465, 52466, 52467, 53219, 53220, 53221, 53223, 53224, 53225, 53227, 53228, 53229, 53230, 53231, 53315, 53791, 53792, 53793, 53794, 53796, 53797, 53798, 53799, 53800, 54572, 54573, 54574, 54575, 54576, 54577, 54578, 54579, 54580, 54581, 54582, 54583, 54584, 54585, 54586, 55257, 55260, 55264, 55266, 55274, 55276, 55277, 55278, 55292, 55304, 55306, 55308, 55310, 55311, 55313, 55314, 55316, 55317, 55318, 55319, 55320, 55321, 55322, 55323, 55324, 55325, 55340, 55342, 55857, 55922, 55924, 55926, 55927, 55930, 55931, 55932, 56118, 56119, 56120, 56121, 56123, 56125, 56126, 56127, 56128, 56129, 56130, 56131, 56135, 56136, 56140, 56151, 56153, 56154, 56155, 56301, 56302, 56306, 56611, 56612, 56613, 56614, 56616, 56618, 56621, 56625, 56627, 56629, 56630, 56631, 56632, 56633, 56634, 56635, 56636, 56637, 56641, 56642, 56643, 56644, 56646);
  script_osvdb_id(34905, 35700, 35920, 43258, 48746, 48747, 48748, 48749, 48750, 48751, 48759, 48760, 48761, 48762, 48763, 48764, 48765, 48766, 48767, 48768, 48769, 48770, 48771, 48772, 48773, 48779, 48780, 49073, 49925, 49995, 50139, 50140, 50141, 50142, 50176, 50177, 50178, 50179, 50181, 50182, 50210, 50285, 51284, 51285, 51286, 51287, 51288, 51289, 51290, 51291, 51292, 51293, 51294, 51295, 51296, 51297, 51925, 51926, 51927, 51928, 51929, 51930, 51931, 51932, 51933, 51934, 51935, 51936, 51937, 51938, 51939, 51940, 52444, 52445, 52446, 52447, 52448, 52449, 52450, 52451, 52452, 52657, 52659, 52896, 53079, 53307, 53341, 53952, 53953, 53954, 53955, 53957, 53958, 53959, 53960, 53961, 53962, 53963, 53964, 53965, 53966, 53967, 53968, 53969, 53970, 53971, 53972, 54174, 55133, 55138, 55139, 55140, 55141, 55142, 55143, 55144, 55145, 55146, 55147, 55148, 55152, 55153, 55154, 55155, 55157, 55158, 55159, 55160, 55161, 55162, 55163, 55164, 55197, 55532, 55846, 55931, 55932, 56218, 56219, 56220, 56221, 56222, 56223, 56224, 56225, 56226, 56227, 56228, 56229, 56230, 56231, 56232, 56253, 56406, 56471, 56484, 56716, 56717, 56718, 56719, 56721, 56723, 56724, 56782, 57003, 57844, 57970, 57971, 57972, 57973, 57975, 57976, 57977, 57978, 57979, 57980, 59381, 59382, 59383, 59384, 59385, 59386, 59388, 59389, 59390, 59392, 59393, 59394, 59395, 59968, 59969, 59970, 59971, 59972, 59974, 60366, 60425, 60521, 61091, 61092, 61093, 61094, 61095, 61096, 61097, 61098, 61099, 61100, 61101, 61102, 61103, 61234, 61638, 61718, 61784, 61785, 61929, 62064, 62135, 62210, 62273, 62416, 62418, 62419, 62420, 62421, 62422, 62423, 62424, 62425, 62426, 62427, 62428, 62464, 62467, 62536, 62877, 63263, 63264, 63265, 63266, 63267, 63268, 63269, 63270, 63271, 63272, 63273, 63457, 63460, 63461, 63462, 63463, 63464, 63465, 63466, 63479, 63620, 63637, 64040, 64070, 64150, 64499, 64725, 65202, 65734, 65735, 65736, 65739, 65742, 65744, 65749, 65750, 65751, 65752, 65852, 66315, 66590, 66591, 66592, 66593, 66594, 66595, 66596, 66597, 66598, 66599, 66600, 66601, 66602, 66603, 66604, 66605, 66786, 67029, 67502, 67900, 67901, 67902, 67903, 67904, 67905, 67906, 67907, 67908, 67910, 67911, 67912, 67913, 68047, 68048, 68079, 68844, 68845, 68846, 68847, 68848, 68849, 68850, 68851, 68853, 68854, 68905, 68921, 69032, 69561, 69758, 69768, 69769, 69770, 69771, 69772, 69773, 69774, 69775, 69776, 69777, 69778, 69779, 69780, 70055, 70620, 71951, 71961, 72074, 72075, 72076, 72077, 72078, 72080, 72081, 72082, 72083, 72084, 72085, 72086, 72087, 72088, 72089, 72090, 72094, 72437, 72438, 72439, 72440, 72441, 72442, 72443, 72444, 72445, 72446, 72447, 72448, 72449, 72454, 72456, 72457, 72458, 72459, 72460, 72461, 72465, 72466, 72467, 72475, 72490, 73177, 73178, 73179, 73180, 73181, 73182, 73183, 73184, 73185, 73186, 73187, 73188, 73192, 73193, 73801, 74319, 74335, 74378, 74581, 74582, 74583, 74584, 74585, 74586, 74587, 74588, 74589, 74590, 74591, 74592, 74593, 74594, 74596, 74829, 75622, 75834, 75835, 75836, 75837, 75838, 75839, 75840, 75841, 75842, 75843, 75844, 75845, 75846, 75847, 76858, 76947, 76948, 76949, 76950, 76951, 76952, 76953, 76954, 76955, 77539, 77609, 77832, 77951, 77952, 77953, 77954, 77956, 78733, 78736, 78737, 79216, 79294, 80011, 80012, 80013, 80014, 80015, 80016, 80017, 80018, 80019, 80020, 80021, 80740, 81513, 81514, 81515, 81516, 81517, 81519, 81520, 81521, 81522, 81523, 81524, 81526, 81650, 81963, 82665, 82666, 82667, 82669, 82673, 82674, 82675, 82676, 82677, 83995, 83996, 83997, 83998, 83999, 84000, 84001, 84002, 84003, 84004, 84005, 84006, 84007, 84008, 84009, 84010, 84011, 84012, 84013, 84959, 84960, 84961, 84962, 84963, 84964, 84965, 84968, 84969, 84970, 84971, 84972, 84973, 84974, 84975, 84989, 84990, 84991, 84992, 84993, 84994, 84995, 84996, 84997, 84999, 85000, 85001, 85003, 85004, 85005, 85926, 86094, 86095, 86096, 86097, 86098, 86099, 86100, 86101, 86102, 86104, 86105, 86106, 86108, 86109, 86110, 86111, 86112, 86113, 86114, 86115, 86116, 86117, 86124, 86125, 86126, 86128, 86171, 86773, 86774, 86775, 87581, 87582, 87584, 87585, 87587, 87588, 87589, 87590, 87591, 87592, 87593, 87594, 87595, 87596, 87597, 87598, 87599, 87601, 87605, 87606, 87607, 87608, 87609);
  script_xref(name:"GLSA", value:"201301-01");

  script_name(english:"GLSA-201301-01 : Mozilla Products: Multiple vulnerabilities (BEAST)");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-201301-01
(Mozilla Products: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Mozilla Firefox,
      Thunderbird, SeaMonkey, NSS, GNU IceCat, and XULRunner. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to view a specially crafted web
      page or email, possibly resulting in execution of arbitrary code or a
      Denial of Service condition. Furthermore, a remote attacker may be able
      to perform Man-in-the-Middle attacks, obtain sensitive information,
      bypass restrictions and protection mechanisms, force file downloads,
      conduct XML injection attacks, conduct XSS attacks, bypass the Same
      Origin Policy, spoof URL&rsquo;s for phishing attacks, trigger a vertical
      scroll, spoof the location bar, spoof an SSL indicator, modify the
      browser&rsquo;s font, conduct clickjacking attacks, or have other unspecified
      impact.
    A local attacker could gain escalated privileges, obtain sensitive
      information, or replace an arbitrary downloaded file.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://blog.mozilla.org/security/2011/03/22/firefox-blocking-fraudulent-certificates/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1f6767f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201301-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Firefox users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-10.0.11'
    All users of the Mozilla Firefox binary package should upgrade to the
      latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-bin-10.0.11'
    All Mozilla Thunderbird users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=mail-client/thunderbird-10.0.11'
    All users of the Mozilla Thunderbird binary package should upgrade to
      the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=mail-client/thunderbird-bin-10.0.11'
    All Mozilla SeaMonkey users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/seamonkey-2.14-r1'
    All users of the Mozilla SeaMonkey binary package should upgrade to the
      latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/seamonkey-bin-2.14'
    All NSS users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/nss-3.14'
    The &ldquo;www-client/mozilla-firefox&rdquo; package has been merged into the
      &ldquo;www-client/firefox&rdquo; package. To upgrade, please unmerge
      &ldquo;www-client/mozilla-firefox&rdquo; and then emerge the latest
      &ldquo;www-client/firefox&rdquo; package:
      # emerge --sync
      # emerge --unmerge 'www-client/mozilla-firefox'
      # emerge --ask --oneshot --verbose '>=www-client/firefox-10.0.11'
    The &ldquo;www-client/mozilla-firefox-bin&rdquo; package has been merged into
      the &ldquo;www-client/firefox-bin&rdquo; package. To upgrade, please unmerge
      &ldquo;www-client/mozilla-firefox-bin&rdquo; and then emerge the latest
      &ldquo;www-client/firefox-bin&rdquo; package:
      # emerge --sync
      # emerge --unmerge 'www-client/mozilla-firefox-bin'
      # emerge --ask --oneshot --verbose '>=www-client/firefox-bin-10.0.11'
    The &ldquo;mail-client/mozilla-thunderbird&rdquo; package has been merged into
      the &ldquo;mail-client/thunderbird&rdquo; package. To upgrade, please unmerge
      &ldquo;mail-client/mozilla-thunderbird&rdquo; and then emerge the latest
      &ldquo;mail-client/thunderbird&rdquo; package:
      # emerge --sync
      # emerge --unmerge 'mail-client/mozilla-thunderbird'
      # emerge --ask --oneshot --verbose '>=mail-client/thunderbird-10.0.11'
    The &ldquo;mail-client/mozilla-thunderbird-bin&rdquo; package has been merged
      into the &ldquo;mail-client/thunderbird-bin&rdquo; package. To upgrade, please
      unmerge &ldquo;mail-client/mozilla-thunderbird-bin&rdquo; and then emerge the
      latest &ldquo;mail-client/thunderbird-bin&rdquo; package:
      # emerge --sync
      # emerge --unmerge 'mail-client/mozilla-thunderbird-bin'
      # emerge --ask --oneshot --verbose
      '>=mail-client/thunderbird-bin-10.0.11'
    Gentoo discontinued support for GNU IceCat. We recommend that users
      unmerge GNU IceCat:
      # emerge --unmerge 'www-client/icecat'
    Gentoo discontinued support for XULRunner. We recommend that users
      unmerge XULRunner:
      # emerge --unmerge 'net-libs/xulrunner'
    Gentoo discontinued support for the XULRunner binary package. We
      recommend that users unmerge XULRunner:
      # emerge --unmerge 'net-libs/xulrunner-bin'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-772");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(16, 20, 22, 59, 79, 94, 119, 189, 200, 264, 287, 310, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:icecat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xulrunner-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list(), vulnerable:make_list("le 3.5.6"))) flag++;
if (qpkg_check(package:"www-client/seamonkey-bin", unaffected:make_list("ge 2.14"), vulnerable:make_list("lt 2.14"))) flag++;
if (qpkg_check(package:"net-libs/xulrunner-bin", unaffected:make_list(), vulnerable:make_list("le 1.8.1.19"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird-bin", unaffected:make_list("ge 10.0.11"), vulnerable:make_list("lt 10.0.11"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird", unaffected:make_list("ge 10.0.11"), vulnerable:make_list("lt 10.0.11"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird-bin", unaffected:make_list(), vulnerable:make_list("le 3.0"))) flag++;
if (qpkg_check(package:"www-client/icecat", unaffected:make_list(), vulnerable:make_list("le 10.0-r1"))) flag++;
if (qpkg_check(package:"dev-libs/nss", unaffected:make_list("ge 3.14"), vulnerable:make_list("lt 3.14"))) flag++;
if (qpkg_check(package:"www-client/firefox-bin", unaffected:make_list("ge 10.0.11"), vulnerable:make_list("lt 10.0.11"))) flag++;
if (qpkg_check(package:"www-client/seamonkey", unaffected:make_list("ge 2.14-r1"), vulnerable:make_list("lt 2.14-r1"))) flag++;
if (qpkg_check(package:"www-client/firefox", unaffected:make_list("ge 10.0.11"), vulnerable:make_list("lt 10.0.11"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird", unaffected:make_list(), vulnerable:make_list("le 3.0.4-r1"))) flag++;
if (qpkg_check(package:"net-libs/xulrunner", unaffected:make_list(), vulnerable:make_list("le 2.0-r1"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list(), vulnerable:make_list("le 3.6.8"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Products");
}
