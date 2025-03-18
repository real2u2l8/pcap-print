# pcap-print

이 프로젝트는 패킷 캡처 및 분석을 위한 도구입니다. 이 도구는 Ethernet, IP, TCP 헤더를 포함한 다양한 네트워크 프로토콜의 패킷을 처리하고 분석하는 기능을 제공합니다.

## 기능
- Ethernet 헤더 구조체 정의
- IP 헤더 구조체 정의
- TCP 헤더 구조체 정의
- 패킷의 IP 버전 및 길이 계산
- TCP 길이 및 오프셋 계산
- 패킷 캡처 및 출력

## 사용법
1. 프로젝트를 클론합니다.
2. 사용된 라이브러리를 설치합니다.
3. CMake를 사용하여 빌드합니다.
4. 생성된 실행 파일을 사용하여 패킷을 캡처하고 분석합니다.

## 사용된 라이브러리 
```bash
sudo apt-get install libpcap-dev
```

## 빌드
```bash
mkdir build
cd build
cmake ..
make
```

## 실행
```bash
sudo ./pcap-print <interface>
```
