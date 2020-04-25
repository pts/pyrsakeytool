#! /usr/bin/python
# by pts@fazekas.hu at Sat Apr 25 19:20:59 CEST 2020

import binascii
import sys
import unittest

import rsakeytool

# six-like compatibility layer between Python 2.x and Python 3.x.
from rsakeytool import bb

DROPBEAR_DATA = binascii.unhexlify(bb('000000077373682d727361000000030100010000020100c7e5c2aaa8e9e8be55a16277ab0c60d5249c0996578ae1e63261664c3b08e42ce69af7817255d0c2b3cc640b311e7d76cf1a346839905195045a040c819bd2227300130a1a7ebe78609d69c0170a1362acd57e2a605b035ae9a4904d322621079b1484640269b7a115997ced3a1fb06e7e298ad57746a7395d9b09893e7d63c48f802132cd9c530a80af0d253705dfb1212adae3a29642aeeb18c52103ec8b5a731e65af07a6b1667e385f9208c7e41ef22085f9af955b373ecc96b04b20b24a9f835ec1787b4e5471a459b7ac23a3e8e1ee8c915081a1ee4a55a13c2b077f6c58aa7db1e4badcf670c24ff14c179146e573eb99db77bdf3a83bce808185b194953d5ccc78be03ec7665c6bab34a7fe45bfb306efa8d1e5e9dc2403ef66a1da2cae70b7026c5223782ae28252eac0103715e2e4341b9040d46f886bd198ccd832fddc3b977fa73015535927ed7813f62453722a3e64e3cec779bda447cd2455da608ea227cd35dfc69db9bced50d9c3d826bc8db25d7657a6268084dd8c267e36cc7882df00ae583deab706c558a60509dbfeb4a098c4df466c44bd86e7d28e53480f2c855b7b6688ebd1e1d1c4ae0e61718f114c88e274833dbdb058721d37aa43ff1e0d33dd14fc4463d86f0fe7f32fb438204536f67f25cfc7d85d6eb58e5122533ee69c7eda10f95b1a5217a23c25ef57292b571d60919ee20737cafff0900000201008b682fe7a6df6222834386916067c48c40f8d532d52095445df4514c6e8b57ddfc812c85494091d38762ce8e8395f8f7c79d45d93df3e9015cc48e384e9765e8027d95c9a10aad38f4603364f46c61729a885571a63b32cecf4ca61a4014194add9b646cfec5cd7b78bdcf42fe1b258719534d706bbb8959d76f0d2a7abb25bdea39f86d1eb99bac226c726576c710e6cdf3be2dacb0d0167efc8a55e90fa96bce06eff12e0bd182621a5c8452bd5cd93c10f47e5a367623c417182c2068d00e7cca386602e9338a6eaaa8ab1050d6b9cdfef8674b56eca06b94e65a38c404d881c97cd97863dd3fbd09b688d881431ec75c9d7d727242b5cfa8cdee0ee6371de50d4c4285c090baeebe8751242a6b9ee9fda9fa5a6fd93db08e52fcb92226bbd589ab5f31b01669e0c812fbae47fc1812f1619502a3cf8b3e592394f3b466293e9d355d17fef3b39afc137460f1e60746f62260a2fe2f419385e9a762cb18ad9a79d497ac9476d8c0a9fac34ea90729749ff6e0efbfe9f2976d1c6274a5e694118dfd1eb941f76f125ca85e1983bb8733dde8cca23f16fc0047f1a4b4959788764e1efdd2b292a8f54c6f11eea8bef5a262b75b9282f5528da9a7a7bf2d69cabee340238ad11d0f49333422fbded7df44d83b5a9c4d34e9b2113a7bf6a169a490afbcb48b12db4bf4920db53c376b7d7bcbd9a9859eeaaa31672bd38fb2f8250000010100f0710459cd01a206f4c4dbb8cd591c3f240c887c11bfef21d00cb0b973e4adafb373c1fec279252771e78f0cde980723f97c5457e72648e2eafaea98414eb8448be103e0e276c0a772735e9eacb45e2ac8d03562ea2c72fb1b83c101e6355aae764dff1fcd7f18ea3c8c384052e64cff91a23085d1149d9ed6c7e3bfa1e09735d6ebfeb981ed168c4942f384570c54b07c01e61afc9277a959147715ec17a29fc0a41e4c694813f755ba4f5ba21f221c0ac7d44e499e0856c66c1330b4d32f09e7b4f3bb47f6a564d381872e0d2b1b3c3dc132d31500e7fa7bde2c302a217bedba964d2dbc02d84b47cbe8bafac184963e65b028d9f6fa71b975440d0513aea30000010100d4d51ee89043051536d581b984820ba0925c006b327490ac010b27780b4612873d7c1ed1accd4e994518a51252de889410c8fefdb7fbfe05352506897a8e507eda7063ff33adda4020be19a32b26d13f35c0aa92d67cdca855561feb0e8d929481e29ce65906acc37eb514ac9b4743d8b6605ff6caa4abb1372c5b6d3c15639fc441cf5780f5dce59dc71c04e41b396bb84162b6d26f33b83ab6f63635f637d0dc36d263ba78c1bd0ba80726cda6ec09e90cd4933948ec17d43762f54c3fa8d33ed90b62204f35ba8b9354addbf227437ff5fe7f6602a3377f48a5e4db2fadd97b02ffe394a9cf2ffef2bbb1c0fa7b495306a4191aa9f4c5fea6dc9ec5c41263'))

MSBLOB_DATA = binascii.unhexlify(bb('0702000000a4000052534132001000000100010009ffaf7c7320ee1909d671b59272f55ec2237a21a5b1950fa1edc769ee332512e558ebd6857dfc5cf2676f53048243fb327ffef0863d46c44fd13dd3e0f13fa47ad3218705dbdb3348278ec814f11817e6e04a1c1d1ebd8e68b6b755c8f28034e5287d6ed84bc466f44d8c094aebbf9d50608a556c70abde83e50af02d88c76ce367c2d84d0868627a65d725dbc86b823d9c0dd5ce9bdb69fc5dd37c22ea08a65d45d27c44da9b77ec3c4ee6a3223745623f81d77e9235550173fa77b9c3dd2f83cd8c19bd86f8460d04b941432e5e710301ac2e2528ae823722c526700be7caa21d6af63e40c29d5e1e8dfa6e30fb5be47f4ab3bac66576ec03be78cc5c3d9594b1858180ce3ba8f3bd77db99eb73e54691174cf14fc270f6dcbae4b17daa586c7f072b3ca1554aeea18150918ceee1e8a323acb759a471544e7b78c15e839f4ab2204bb096cc3e375b95aff98520f21ee4c708925f387e66b1a607af651e735a8bec0321c518ebae4296a2e3da2a21b1df0537250daf800a539ccd3221808fc4637d3e89099b5d39a74677d58a297e6eb01f3aed7c9915a1b769026484149b072126324d90a4e95a035b602a7ed5ac62130a17c0699d6078be7e1a0a13007322d29b810c045a049551903968341acf767d1e310b64ccb3c2d0557281f79ae62ce4083b4c666132e6e18a5796099c24d5600cab7762a155bee8e9a8aac2e5c7a3ae13050d4475b971faf6d928b0653e9684c1fabae8cb474bd802bc2d4d96baed7b212a302cde7bfae70015d332c13d3c1b2b0d2e8781d364a5f647bbf3b4e7092fd3b430136cc656089e494ed4c70a1c221fa25b4fba55f71348694c1ea4c09fa217ec15771459a97792fc1ae6017cb0540c5784f342498c16ed81b9feebd63597e0a1bfe3c7d69e9d14d18530a291ff4ce65240388c3cea187fcd1fff4d76ae5a35e601c1831bfb722cea6235d0c82a5eb4ac9e5e7372a7c076e2e003e18b44b84e4198eafaeae24826e757547cf9230798de0c8fe771272579c2fec173b3afade473b9b00cd021efbf117c880c243f1c59cdb8dbc4f406a201cd590471f06312c4c59edca6fec5f4a91a19a40653497bfac0b1bbf2fe2fcfa994e3ff027bd9ad2fdbe4a5487f37a302667ffef57f4327f2dbad54938bba354f20620bd93ed3a83f4cf56237d417ec483993d40ce909eca6cd2607a80bbdc178ba63d236dcd037f63536f6b63ab8336fd2b66241b86b391be4041cc79de5dcf58057cf41c49f63153c6d5b2c37b1aba4caf65f60b6d843479bac14b57ec3ac0659e69ce28194928d0eeb1f5655a8dc7cd692aac0353fd1262ba319be2040daad33ff6370da7e508e7a8906253505fefbb7fdfec8109488de5212a51845994ecdacd11e7c3d8712460b78270b01ac9074326b005c92a00b8284b981d53615054390e81ed5d40b402760e89292d6f87fb024a94d5975f7007beed3554615d63cc74f40f7523024744520f59a3f9b5335d5963bd02eacdbf3cc7e205ca4a3b40133d62286e1f454b57921574b4008d0c23c74a5b31ff00cc9a31eb431cebdfc7c5265a12a01c7257e3a946fa4f78bea2f334962c8d14ef700327a54c4895c9aa1af9c84620f778f6b29b1d45058923b36abda3998837125a7f39c942acf2d7d720c46704804d998c29f1f9a80d5e4f2958429eadfeb728ff27870d3839907f7a573d4dd22d2031b322edfb0a64da1ce51a2b21a142b24d9fd31ff6032be8333184b49ae1aa93be5949c687fedf5ee00c106588f2c060bb8ad2faa312ed7bfe1d24e3a946706359b56905c4b009ea8a78da0c9f50842db4117b2d43a4d3b5db1be41d8374b515a03125b3e61d2b03fdf8876ceed9ab4038c9384971bb918228d9bdaa681b460ae6d624d4664f85a0f024c4d7a8a58800ef0827ee09d17e75bf175250245ecf6bc019d953b5a93dabba0266c605565ed56506800b3b5dbbfcae51f594ba8159637662c520e15c87e5537b91afa196894b7d7d28abeadb5a8627b73f6a203639d8180f7b62b413d8e2519e192c3149ddd1cbd2420e9a241e41654627870df7f9683ba6b1e50edeb33e408ec8bf7990e6dca86d5bc7e38e202b4c563893b2cefe743a03cd76f40c87e857faf3455c6f3d9f5a8da3c8719520d6fd23a7fc5258fce672a36c1b2b1a7a3a5918961ddd48248cbb2790d6de6686500e1c13fc9447d696e87f1dd3c93e7e8d18207c63759109d3e1f75f2a87b05bca21f82ee0a9cf0958a5b0d6a6b8c8493153871c18874def6e5230259762ba9eb4371a7f0373463a44f83c0626eb7a3c2fce0fe9330a3d104bd300a85080a98319db11eb8aed072b2757c415a2a502503099ee67d8413b760dffaa78f69a04a91c3d712d969018754b88d02d2c6532c3501663a5443e2fd2c23d6ee56023a0fda830a5d5b22fd8feec6bc0ecde40b183753aee87571db5bf56b6a7d046218a949a4c46e30ce8e3fc7c7bfa11fab028586a9fcf908c028837621ba98c3681711959c8813a82f5271623925f8b28fd32b6731aaea9e85a9d9cb7b7d6b373cb50d92f44bdb128bb4bcaf90a469a1f67b3a11b2e9344d9c5a3bd844dfd7defb223433490f1dd18a2340e3beca692dbfa7a7a98d52f582925bb762a2f5bea8ee116f4cf5a892b2d2fd1e4e76889795b4a4f14700fc163fa2cce8dd3387bb83195ea85c126ff741b91efd8d1194e6a574621c6d97f2e9bfefe0f69f742907a94ec3faa9c0d87694ac97d4799aad18cb62a7e98593412ffea26022f64607e6f1607413fc9ab3f3fe175d359d3e2966b4f39423593e8bcfa3029561f11218fc47aefb12c8e06916b0315fab89d5bb2622b9fc528eb03dd96f5afaa9fde99e6b2a245187beeeba90c085424c0de51d37e60eeecda8cfb54272727d9d5cc71e4381d888b609bd3fdd6378d97cc981d804c4385ae6946ba0ec564b67f8fecdb9d65010aba8aa6e8a33e9026638ca7c0ed068202c1817c42376365a7ef4103cd95cbd52845c1a6282d10b2ef1ef06ce6ba90fe9558afc7e16d0b0ac2dbef3cde610c77665726c22ac9bb91e6df839eabd25bb7a2a0d6fd75989bb6b704d531987251bfe42cfbd787bcdc5fe6c649bdd4a1914401aa64ccfce323ba67155889a72616cf4643360f438ad0aa1c9957d02e865974e388ec45c01e9f33dd9459dc7f7f895838ece6287d3914049852c81fcdd578b6e4c51f45d449520d532d5f8408cc46760918643832262dfa6e72f688b'))

DER2_DATA = binascii.unhexlify(bb('30820942020100300d06092a864886f70d01010105000482092c308209280201000282020100c7e5c2aaa8e9e8be55a16277ab0c60d5249c0996578ae1e63261664c3b08e42ce69af7817255d0c2b3cc640b311e7d76cf1a346839905195045a040c819bd2227300130a1a7ebe78609d69c0170a1362acd57e2a605b035ae9a4904d322621079b1484640269b7a115997ced3a1fb06e7e298ad57746a7395d9b09893e7d63c48f802132cd9c530a80af0d253705dfb1212adae3a29642aeeb18c52103ec8b5a731e65af07a6b1667e385f9208c7e41ef22085f9af955b373ecc96b04b20b24a9f835ec1787b4e5471a459b7ac23a3e8e1ee8c915081a1ee4a55a13c2b077f6c58aa7db1e4badcf670c24ff14c179146e573eb99db77bdf3a83bce808185b194953d5ccc78be03ec7665c6bab34a7fe45bfb306efa8d1e5e9dc2403ef66a1da2cae70b7026c5223782ae28252eac0103715e2e4341b9040d46f886bd198ccd832fddc3b977fa73015535927ed7813f62453722a3e64e3cec779bda447cd2455da608ea227cd35dfc69db9bced50d9c3d826bc8db25d7657a6268084dd8c267e36cc7882df00ae583deab706c558a60509dbfeb4a098c4df466c44bd86e7d28e53480f2c855b7b6688ebd1e1d1c4ae0e61718f114c88e274833dbdb058721d37aa43ff1e0d33dd14fc4463d86f0fe7f32fb438204536f67f25cfc7d85d6eb58e5122533ee69c7eda10f95b1a5217a23c25ef57292b571d60919ee20737cafff09020301000102820201008b682fe7a6df6222834386916067c48c40f8d532d52095445df4514c6e8b57ddfc812c85494091d38762ce8e8395f8f7c79d45d93df3e9015cc48e384e9765e8027d95c9a10aad38f4603364f46c61729a885571a63b32cecf4ca61a4014194add9b646cfec5cd7b78bdcf42fe1b258719534d706bbb8959d76f0d2a7abb25bdea39f86d1eb99bac226c726576c710e6cdf3be2dacb0d0167efc8a55e90fa96bce06eff12e0bd182621a5c8452bd5cd93c10f47e5a367623c417182c2068d00e7cca386602e9338a6eaaa8ab1050d6b9cdfef8674b56eca06b94e65a38c404d881c97cd97863dd3fbd09b688d881431ec75c9d7d727242b5cfa8cdee0ee6371de50d4c4285c090baeebe8751242a6b9ee9fda9fa5a6fd93db08e52fcb92226bbd589ab5f31b01669e0c812fbae47fc1812f1619502a3cf8b3e592394f3b466293e9d355d17fef3b39afc137460f1e60746f62260a2fe2f419385e9a762cb18ad9a79d497ac9476d8c0a9fac34ea90729749ff6e0efbfe9f2976d1c6274a5e694118dfd1eb941f76f125ca85e1983bb8733dde8cca23f16fc0047f1a4b4959788764e1efdd2b292a8f54c6f11eea8bef5a262b75b9282f5528da9a7a7bf2d69cabee340238ad11d0f49333422fbded7df44d83b5a9c4d34e9b2113a7bf6a169a490afbcb48b12db4bf4920db53c376b7d7bcbd9a9859eeaaa31672bd38fb2f8250282010100f0710459cd01a206f4c4dbb8cd591c3f240c887c11bfef21d00cb0b973e4adafb373c1fec279252771e78f0cde980723f97c5457e72648e2eafaea98414eb8448be103e0e276c0a772735e9eacb45e2ac8d03562ea2c72fb1b83c101e6355aae764dff1fcd7f18ea3c8c384052e64cff91a23085d1149d9ed6c7e3bfa1e09735d6ebfeb981ed168c4942f384570c54b07c01e61afc9277a959147715ec17a29fc0a41e4c694813f755ba4f5ba21f221c0ac7d44e499e0856c66c1330b4d32f09e7b4f3bb47f6a564d381872e0d2b1b3c3dc132d31500e7fa7bde2c302a217bedba964d2dbc02d84b47cbe8bafac184963e65b028d9f6fa71b975440d0513aea30282010100d4d51ee89043051536d581b984820ba0925c006b327490ac010b27780b4612873d7c1ed1accd4e994518a51252de889410c8fefdb7fbfe05352506897a8e507eda7063ff33adda4020be19a32b26d13f35c0aa92d67cdca855561feb0e8d929481e29ce65906acc37eb514ac9b4743d8b6605ff6caa4abb1372c5b6d3c15639fc441cf5780f5dce59dc71c04e41b396bb84162b6d26f33b83ab6f63635f637d0dc36d263ba78c1bd0ba80726cda6ec09e90cd4933948ec17d43762f54c3fa8d33ed90b62204f35ba8b9354addbf227437ff5fe7f6602a3377f48a5e4db2fadd97b02ffe394a9cf2ffef2bbb1c0fa7b495306a4191aa9f4c5fea6dc9ec5c4126302820100350667943a4ed2e1bfd72e31aa2fadb80b062c8f5806c100eef5ed7f689c94e53ba91aae494b183383be3260ff31fdd9242b141ab2a251cea14da6b0df2e321b03d222ddd473a5f7079983d37078f28f72ebdfea298495f2e4d5809a1f9fc298d9044870460c727d2dcf2a949cf3a72571839839daab363b925850d4b1296b8f770f62849cafa19a5c89c4547a3200f74ed1c86249332fea8bf7a46f943a7e25c7012aa165527cfcbdce31b41ea3c90cf01fb3a5743cc2d008404b572179b554f4e18622d63301b4a3a45c207eccf3dbac2ed03b96d535539b3f9af5204574243052f7404fc73cd6154655d3ee7b00f775594da924b07ff8d69292e86027400b0282010067ce8f25c57f3ad26f0d5219873cdaa8f5d9f3c65534af7f857ec8406fd73ca043e7ef2c3b8963c5b402e2387ebcd586ca6d0e99f78bec08e433ebed501e6bba83967fdf7078625416e441a2e92024bd1cdd9d14c392e119258e3d412bb6f780819d6303a2f6737b62a8b5adbe8ad2d7b7946819fa1ab937557ec8150e522c66379615a84b591fe5cabfdbb5b300685056ed6555606c26a0bbda935a3b959d01bcf6ec45022575f15be7179de07e82f00e80588a7a4d4c020f5af864464d626dae60b481a6da9b8d2218b91b9784938c03b49aedce7688df3fb0d2613e5b12035a514b37d841beb15d3b4d3ad4b21741db4208f5c9a08da7a89e004b5c90569b02820100396271522fa813889c95111768c398ba21768328c008f9fca9868502ab1fa1bfc7c73f8ece306ec4a449a91862047d6a6bf55bdb7175e8ae5337180be4cd0ebcc6ee8ffd225b5d0a83da0f3a0256eed6232cfde243543a6601352c53c6d2028db854870169d912d7c3914aa0698fa7fadf60b713847de69e090325502a5a417c75b272d0aeb81eb19d31980a08850a30bd04d1a33093fee0fcc2a3b76e62c0834fa4633437f0a77143eba92b76590223e5f6de7488c171381593848c6b6a0d5b8a95f09c0aee821fa2bc057ba8f2751f3e9d105937c60782d1e8e7933cddf1876e697d44c93fc1e1006568e66d0d79b2cb4882d4dd618991a5a3a7b1b2c1362a'))

PEM2_DATA = bb('''-----BEGIN PRIVATE KEY-----
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
aOZtDXmyy0iC1N1hiZGlo6exssE2Kg==
-----END PRIVATE KEY-----
''')


def get_test_rsa_key():
  # Example 4096-bit key (modulus size).
  return rsakeytool.get_rsa_private_key(
      modulus=0x00c7e5c2aaa8e9e8be55a16277ab0c60d5249c0996578ae1e63261664c3b08e42ce69af7817255d0c2b3cc640b311e7d76cf1a346839905195045a040c819bd2227300130a1a7ebe78609d69c0170a1362acd57e2a605b035ae9a4904d322621079b1484640269b7a115997ced3a1fb06e7e298ad57746a7395d9b09893e7d63c48f802132cd9c530a80af0d253705dfb1212adae3a29642aeeb18c52103ec8b5a731e65af07a6b1667e385f9208c7e41ef22085f9af955b373ecc96b04b20b24a9f835ec1787b4e5471a459b7ac23a3e8e1ee8c915081a1ee4a55a13c2b077f6c58aa7db1e4badcf670c24ff14c179146e573eb99db77bdf3a83bce808185b194953d5ccc78be03ec7665c6bab34a7fe45bfb306efa8d1e5e9dc2403ef66a1da2cae70b7026c5223782ae28252eac0103715e2e4341b9040d46f886bd198ccd832fddc3b977fa73015535927ed7813f62453722a3e64e3cec779bda447cd2455da608ea227cd35dfc69db9bced50d9c3d826bc8db25d7657a6268084dd8c267e36cc7882df00ae583deab706c558a60509dbfeb4a098c4df466c44bd86e7d28e53480f2c855b7b6688ebd1e1d1c4ae0e61718f114c88e274833dbdb058721d37aa43ff1e0d33dd14fc4463d86f0fe7f32fb438204536f67f25cfc7d85d6eb58e5122533ee69c7eda10f95b1a5217a23c25ef57292b571d60919ee20737cafff09,
      public_exponent=0x10001,
      prime1=0x00f0710459cd01a206f4c4dbb8cd591c3f240c887c11bfef21d00cb0b973e4adafb373c1fec279252771e78f0cde980723f97c5457e72648e2eafaea98414eb8448be103e0e276c0a772735e9eacb45e2ac8d03562ea2c72fb1b83c101e6355aae764dff1fcd7f18ea3c8c384052e64cff91a23085d1149d9ed6c7e3bfa1e09735d6ebfeb981ed168c4942f384570c54b07c01e61afc9277a959147715ec17a29fc0a41e4c694813f755ba4f5ba21f221c0ac7d44e499e0856c66c1330b4d32f09e7b4f3bb47f6a564d381872e0d2b1b3c3dc132d31500e7fa7bde2c302a217bedba964d2dbc02d84b47cbe8bafac184963e65b028d9f6fa71b975440d0513aea3)


class RsakeytoolTest(unittest.TestCase):
  maxDiff = None

  def test_convert(self):
    d = get_test_rsa_key()
    assert rsakeytool.is_rsa_private_key_complete(d)
    convert_rsa_data = rsakeytool.convert_rsa_data
    der = convert_rsa_data(d, 'der')
    pem = convert_rsa_data(d, 'pem')
    der2 = convert_rsa_data(d, 'der2')
    pem2 = convert_rsa_data(d, 'pem2')
    assert convert_rsa_data(der, 'der') == der
    assert convert_rsa_data(pem, 'der') == der
    assert convert_rsa_data(der2, 'der') == der
    assert convert_rsa_data(pem2, 'der') == der
    assert convert_rsa_data(der, 'dict') == d
    assert convert_rsa_data(convert_rsa_data(der, 'dropbear'), 'der') == der
    assert convert_rsa_data(convert_rsa_data(der, 'msblob'), 'der') == der
    d = {'public_exponent': 5, 'prime1': 23, 'prime2': 29}
    dd = {'public_exponent': 5, 'private_exponent': 493, 'prime1': 29, 'prime2': 23, 'modulus': 667, 'exponent1': 17, 'exponent2': 9, 'coefficient': 24}
    self.assertEqual(dd, convert_rsa_data(d, 'dict'))
    self.assertEqual(bb('modulus = 0x29b\npublic_exponent = 0x5\nprivate_exponent = 0x1ed\nprime1 = 0x1d\nprime2 = 0x17\nexponent1 = 0x11\nexponent2 = 0x9\ncoefficient = 0x18\n'),
                     convert_rsa_data(d, 'hexa'))
    hexa_data = bb('n  = 0x29b\npublic_exponent   =5\nprivate_exponent\t\r=\n0x1Ed\nprime1 = 0x1d\nprime2 = 23\nexponent1 = 0x11\nexponent2 = 0x9\ncoefficient = 0X18\n')
    self.assertEqual(dd, convert_rsa_data(bb(' \t\r\n  ') + hexa_data, 'dict'))
    self.assertEqual(dd, convert_rsa_data(hexa_data, 'dict'))

  def test_golden(self):
    d = get_test_rsa_key()
    convert_rsa_data = rsakeytool.convert_rsa_data
    assert convert_rsa_data(d, 'dropbear') == DROPBEAR_DATA
    assert convert_rsa_data(DROPBEAR_DATA, 'dict') == d
    assert convert_rsa_data(d, 'msblob') == MSBLOB_DATA
    assert convert_rsa_data(MSBLOB_DATA, 'dict') == d
    assert convert_rsa_data(d, 'der2') == DER2_DATA
    assert convert_rsa_data(DER2_DATA, 'dict') == d
    assert convert_rsa_data(d, 'pem2') == PEM2_DATA
    assert convert_rsa_data(PEM2_DATA, 'dict') == d


if __name__ == '__main__':
  unittest.main(argv=[sys.argv[0], '-v'] + sys.argv[1:])
