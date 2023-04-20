Анализатор сетевого трафика __Sniffer__ (_Задание №1 Дубровский Е.С._)
___
# Оглавление
* __Сборка проекта__
  * Требования к сборке
  * Пример сборки через консоль
* __Запуск программы__
  * Запуск программы с аргументами командной строки
  * Запуск Unit тестов
  * Просмотр лог-файла
* __Документация Doxygen__
___
- [X] __Сборка проекта__

### Требования к сборке
  Сборка проекта осуществляется на [CMake](https://cmake.org/download/) версии __3.2__ и выше. Компилятор должен поддерживать __C++11__.
  
  Зависимости: __нет__. Все автоматически подтягивается при сборке данного проекта. При реализации использовалась кроссплатформенная библиотека [PcapPlusPlus](https://pcapplusplus.github.io/). Для логгирования использовалась [spdlog](https://github.com/gabime/spdlog). Для Unit тестирования использовался [GTest](https://github.com/google/googletest).
  
  ### Пример сборки через консоль
  
  1. Скачиваем репозиторий и создаем новую директорию для сборки проекта:
  ```
  $ git clone https://github.com/Eugene-beginning-of-the-path/Sniffer
  $ cd Sniffer && mkdir build && cd build
  ```
  
  2. Генерируем проектные файлы и собираем проект:
  ```
  $ cmake ..
  $ make
  ```
___
- [X] __Запуск программы__

### Запуск программы с аргументами командной строки

Вы можете просмотреть информацию о необходимых аргументах для запуска программы через --help.
Из директории сборки:
```
$ ./src/snifferApp --help
```
Вы можете запустить работу сниффера для прослушивания порта на определенное кол-во секунд, либо передать на вход программе имя файла .pcap с информацией о сырых пакетах.

Для запуска сниффера на прослушивание порта:

>snifferApp -<time_capture> -<name_interface> -<working_mode>

Аргументы:

__-<time_capture>__ Время прослушивания порта в секундах.

__-<name_interface>__ Имя сетевого интерфейса. Вы можете узнать информацию о ваших сетевых интерфейсах, выполнив команду `$ ip addr` либо `$ ifconfig`

__-<working_mode>__ Сниффер может прослушивать порт в течении указанного кол-ве секунд и после предоставить информацию в консоль с различной подробностью. К примеру в режиме __'brief'__, сниффер предоставит в консоль общее кол-во протоколов из всех пойманных пакетов за указанный диапазон времени.

Пример результата работы __'brief'__ режима:
```
Ethernet packet count: 585
IPv4 packet count:     583
IPv6 packet count:     0
TCP packet count:      535
UDP packet count:      48
DNS packet count:      48
HTTP packet count:     24
SSL packet count:      0
```

В режиме __'full'__ помимо вывода той же статистике о кол-ве протоколов, добавится подробная информация о каждом пойманном пакете и его слоях (протоколах).

Пример результата работы второго режима __'full'__:
```
Ethernet packet count: 14
IPv4 packet count:     14
IPv6 packet count:     0
TCP packet count:      10
UDP packet count:      4
DNS packet count:      4
HTTP packet count:     2
SSL packet count:      0
```
и ниже представлена информация о парсинге всех пойманных пакетов. Для примера, 8-ой пойманный пакет:
```
Packet #8:
        Ethernet:
                >Source MAC address: 00:15:5d:7d:59:a6
                >Destination MAC address: 00:15:5d:a6:86:b8
                >Ethernet Type: 8
                >Payload size: 113

        IPv4:
                >Destination IP: 109.120.167.1
                >Source IP: 172.29.207.80
                >Header lenght: 20
                >into Header:
                |       -IP id: 14575
                |       -Time live: 64
                |       -Total len: 28928
                |       -Header checksum: 26299
                |       -Protocol: 6

        TCP:
                >Source port: 34872
                >Destination port: 80
                >Header len: 20
                >into Header:
                |       -Acknowledgment number: 1
                |       -PSH flag: 1
                |       -Size of the recieve window: 62977                
                |       -Sequence number: 2872115166
                |       -Checksum field: 19344
                |       -Size of the TCP header in 32-bit words: 19344

        HTTP(request):
                >Size: 16
                >Method: GET
                >URI: /
                >Host: alfada.ru
                >User-agent: curl/7.81.0
                >HTTP full URL: alfada.ru/
```
Для подсчета кол-ва общего количества URL у пойманных пакетов с протоколом HTTP, используйте __'protei'__ режим. В результате в коноли отобразиться статистика по количеству общего числа протоколов у пойманных пакетов, их разбор, и в самом низу будет представлена кол-во URL, у пойманных пакетов с HTTP протоколом. 

Пример результата работы третьего режима __'protei'__:
```
Ethernet packet count: 178
IPv4 packet count:     176
IPv6 packet count:     0
TCP packet count:      164
UDP packet count:      12
DNS packet count:      12
HTTP packet count:     6
SSL packet count:      0

 Packet #1:
        Ethernet:
                >Source MAC address: 00:15:5d:7d:59:a6
                >Destination MAC address: 00:15:5d:a6:86:b8
                >Ethernet Type: 8
                >Payload size: 55

        IPv4:
                >Destination IP: 172.29.192.1
                >Source IP: 172.29.207.80
                >Header lenght: 20
                >into Header:
                |       -IP id: 63754
                |       -Time live: 64
                |       -Total len: 14080
                |       -Header checksum: 12360
                |       -Protocol: 17

        UDP:
                >Source port: 36480
                >Destination port: 53
                >Header len: 8
                >Payload size: 27
                >into Header:
                |       -Length of header and payload in bytes: 8960
                |       -Checksum field: 49639

        DNS:
                >Size of the DNS data : 27
                >Payload size: 0
                >Query count: 1
                >Answer count: 0
                >Authority count: 0
                >Additional record count: 0
                >into Header:
                |       -DNS Query ID: 43224
                |       -Number DNS query records: 256
                |       -Number DNS answer records: 0
                |       -Number authority records: 0
                |       -Number additional records: 0
                >DNS query:
                |       -Query size: 15
                |       -Query type: DNS query record
```
процесс вывода информации о еще 176 пакетов...

И в самом конце располложена интересующая нас информация о кол-ве URL:
```
-----------------------------------------------------

Protei task:
         URL:'alfada.ru' = 12
         URL:'htmlbook.ru' = 4
         URL:'spb.avtotochki.ru' = 8
```   


Пример запуска сниффера для прослушивания сетевого интерфейса _eth0_ на _15 секунд_ в режиме _protei_ для подсчета кол-ва URL из HTTP протоколов:

>$ sudo ./src/snifferApp  -15 -eth0 -protei

И после параллельно отправлю HTTP пакеты на некоторые сервера:

>$ curl 'http://alfada.ru' && curl 'http://www.vk.com' && curl 'http://alfada.ru' && curl 'http://htmlbook.ru' && curl 'http://spb.avtotochki.ru'
___
Для запуска сниффера на чтение файла:

>*snifferApp -<file_name.pcap>

__-<file_name.pcap>__ Имя файла, чтение которого нужно произвести. Данный файл _должен быть самостоятельно помещен заранее_ в директорию сборки проекта. Для примера можете взять input.pcap файл из директории Sniffer/SnifferLib/FilesToRead/ и переместить файл в директорию сборки проекта, чтобы предоставить его для работы программы:

>$ sudo ./src/snifferApp  -input.pcap

___

### Запуск Unit тестов

Переместите файл input.pcap из директории Sniffer/SnifferLib/FilesToRead/ в директорию сборки проекта. В текущих тестах для полноценного тестирования функционала сниффера, включено тестирование результатов чтения .pcap файла. Вы можете это быстро, выполнив команду `$ cp ../SnifferLib/FilesToRead/input.pcap` .

И после запустите тесты из директории сборки проекта:

>$ sudo ./SnifferLib/Tests/snifferTest

Если файл input.pcap будет в директории сборки, то все тесты пройдут успешно:
```
[==========] Running 2 tests from 2 test suites.
[----------] Global test environment set-up.
[----------] 1 test from SomeSuite
[ RUN      ] SomeSuite.checkThrow
[ERROR: /home/eug/projects/Sniffer/external/PcapPlusPlus/Pcap++/src/PcapFileDevice.cpp: open:261] Cannot open file reader device for filename 'in': in: No such file or directory
Cannot open input.pcap for reading
EXPECT_THROW #1 - DONE
EXPECT_THROW #2 - DONE
EXPECT_THROW #3 - DONE
[       OK ] SomeSuite.checkThrow (28 ms)
[----------] 1 test from SomeSuite (28 ms total)

[----------] 1 test from ParserFixture
>>SetUpTestSuite
[ RUN      ] ParserFixture.sizeOf
>>SetUp
EXPECT_EQ #1 - DONE
EXPECT_EQ #2 - DONE
EXPECT_EQ #3 - DONE
EXPECT_GE #1 - DONE
EXPECT_GE #2 - DONE
>>TearDown
[       OK ] ParserFixture.sizeOf (2 ms)
>>TearDownTestSuite
[----------] 1 test from ParserFixture (2 ms total)

[----------] Global test environment tear-down
[==========] 2 tests from 2 test suites ran. (30 ms total)
[  PASSED  ] 2 tests.
```

### Просмотр лог-файла

После выполнения тестов или успешного запуска программы, из директории сборки вы можете перейти и просмотреть файл логирования: 

>$ cat logs/SnifferLogs.txt
___
- [X] __Документация Doxygen__

В основе данного сниффера находится самописаня библиотека SnifferLib, к которой прилагается документация для дальнейшего развития проекта. Вы можете просмотреть html страницы, сгенерированные Doxygen, пройдя в директорию `Sniffer/SnifferLib/Documentation` и ознакомится с основными пространствами имен и классами.
      
