#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <inttypes.h>
#include <stdbool.h>

#define NELEMS(x)  (sizeof(x) / sizeof(x[0]))

#define BUFFER_SIZE 300

#define AX25_ADDR_SIZE 7

#define KISS_FEND 0xC0
#define KISS_FESC 0xDB
#define KISS_TFEND 0xDC
#define KISS_TFESC 0xDD
#define KISS_DATA_FRAME 0x00

#define CDI_HEADER_SIZE 8

#define SUCCESS 0
#define ERR_BUFFER_FULL 1

typedef struct {
  uint32_t offset;
  uint32_t size;
  uint8_t buffer[BUFFER_SIZE];
} buffer;

buffer kiss_send_buffer;
buffer kiss_recv_buffer;

buffer lithium_send_buffer;
buffer lithium_recv_buffer;

uint8_t dest_addr[] = { 0xA2, 0x84, 0x6A, 0x60, 0xA8, 0xA6, 0x7C };
uint8_t src_addr[] = { 0xA2, 0x84, 0x6A, 0x60, 0xA8, 0xA6, 0x63 };

uint8_t ax25_control_bits = 0x03;
uint8_t ax25_protocol_ident = 0xF0;
uint8_t ax25_frame_status = 0x00;

uint8_t ax25_test_payload[] = {
  0x30, 0x02, 0x01, 0x00, 0x08, 0x0A, 0xC0, 0x01, 0x00, 0x1A, 0x10, 0x03, 0x19,
  0x1C, 0xB9, 0xCF, 0x00, 0x00, 0xFF, 0x00, 0x6E, 0xC4, 0x10, 0x08, 0x52, 0x78,
  0xD5, 0x01, 0x76, 0xD1, 0x14, 0x04, 0x55, 0x77, 0xE2, 0x9F, 0xED, 0x00
};

void buffer_clear(buffer* b) {
  b->offset = 0;
  b->size = 0;
}

void buffer_remove(buffer* b, uint32_t size) {
  b->offset = (b->offset + size) % BUFFER_SIZE;
  b->size = 0;
}

uint8_t buffer_at(buffer* b, uint32_t i) {
  return b->buffer[(b->offset + i) % BUFFER_SIZE];
}

uint32_t buffer_capacity(buffer* b) {
  return BUFFER_SIZE - b->size;
}

int buffer_add(buffer* b, uint8_t* data, uint32_t size) {
  if(b->size + size > BUFFER_SIZE) {
    return ERR_BUFFER_FULL;
  }

  for(uint32_t i = 0; i < size; i++) {
    b->buffer[(b->offset + b->size + i) % BUFFER_SIZE] = data[i];
  }

  b->size += size;
  return SUCCESS;
}

int buffer_copy(buffer* dest, buffer* src, uint32_t start, uint32_t size) {
  if(dest->size + size > BUFFER_SIZE) {
    return ERR_BUFFER_FULL;
  }

  for(uint32_t i = 0; i < size; i++) {
    dest->buffer[(dest->offset + dest->size + i) % BUFFER_SIZE] =
      buffer_at(src, start + i);
  }

  dest->size += size;
  return SUCCESS;
}

void kiss_write_char(int fd, uint8_t c) {
  write(fd, &c, 1);
}

void kiss_write_buffer(int fd, buffer* b) {
  kiss_write_char(fd, KISS_FEND);
  kiss_write_char(fd, KISS_DATA_FRAME);

  for(uint32_t i = 0; i < b->size; i++) {
    uint8_t c = buffer_at(b, i);

    if(c == KISS_FEND) {
      kiss_write_char(fd, KISS_FESC);
      kiss_write_char(fd, KISS_TFEND);
    }
    else if(c == KISS_FESC) {
      kiss_write_char(fd, KISS_FESC);
      kiss_write_char(fd, KISS_TFESC);
    }
    else {
      kiss_write_char(fd, c);
    }
  }

  kiss_write_char(fd, KISS_FEND);
}

int cdi_verify_checksum(buffer* b, uint32_t start, uint32_t size,
    uint8_t ex_chk_a, uint8_t ex_chk_b) {
  uint8_t chk_a = 0;
  uint8_t chk_b = 0;

  for(uint32_t i = 0; i < size; i++) {
    chk_a += buffer_at(b, start + i);
    chk_b += chk_a;
  }

  return (chk_a == ex_chk_a) && (chk_b == ex_chk_b);
}

uint16_t cdi_payload_size(buffer* b) {
  uint16_t size_msb = buffer_at(b, 3);
  return (size_msb << 8) + buffer_at(b, 4);
}

int cdi_check_packet(buffer* b) {
  // The packet must be at least 10 bytes (header + footer)
  if(b->size < 10) {
    return false;
  }

  // Check sync chars
  if(!(buffer_at(b, 0) == 'H' && buffer_at(b, 1) == 'e')) {
    return false;
  }

  // Check header checksum
  uint8_t h_chk_a = buffer_at(b, 6);
  uint8_t h_chk_b = buffer_at(b, 7);
  if(!cdi_verify_checksum(b, 0, CDI_HEADER_SIZE, h_chk_a, h_chk_b)) {
    printf("Wrong header checksum\n");
    return false;
  }

  uint16_t size = cdi_payload_size(b);
  if(b->size < 10 + size) {
    return false;
  }

  uint8_t p_chk_a = b->buffer[CDI_HEADER_SIZE + size];
  uint8_t p_chk_b = b->buffer[CDI_HEADER_SIZE + size + 1];
  if(!cdi_verify_checksum(b, CDI_HEADER_SIZE, size, p_chk_a, p_chk_b)) {
    printf("Wrong checksum\n");
    return false;
  }

  return true;
}

void kiss_write_ax25_header(buffer* dest) {
  buffer_add(dest, dest_addr, AX25_ADDR_SIZE);
  buffer_add(dest, src_addr, AX25_ADDR_SIZE);
  buffer_add(dest, &ax25_control_bits, 1);
  buffer_add(dest, &ax25_protocol_ident, 1);
}

void kiss_write_ax25_payload(buffer* dest, buffer* src) {
  uint16_t payload_size = cdi_payload_size(src);
  buffer_copy(dest, src, CDI_HEADER_SIZE, payload_size);
}

void config_port(int fd) {
  // Blocking reads
  fcntl(fd, F_SETFL, 0);

  struct termios options;
  tcgetattr(fd, &options);

  // Set speed
  cfsetispeed(&options, B9600);
  cfsetospeed(&options, B9600);

  options.c_cflag |= (CLOCAL | CREAD);

  // No parity bit
  options.c_cflag &= ~PARENB;
  options.c_cflag &= ~CSTOPB;
  options.c_cflag &= ~CSIZE;
  options.c_cflag |= CS8;

  // Disable hardware flow control
  options.c_cflag &= ~CRTSCTS;

  // Raw input
  options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

  // Raw output
  options.c_oflag &= ~OPOST;
  options.c_cc[VMIN] = 0;
  options.c_cc[VTIME] = 10;

  tcsetattr(fd, TCSANOW, &options);
}

int main(int argc, char *argv[]) {
  int fd_kiss = open("/dev/ttyf1", O_RDWR | O_NOCTTY | O_NDELAY);
  int fd_lithium = open("/dev/ttyf1", O_RDWR | O_NOCTTY | O_NDELAY);
  if(fd_kiss == -1 || fd_lithium == -1) {
    perror("Unable to open serial port");
    return -1;
  }

  config_port(fd_kiss);
  config_port(fd_lithium);

  kiss_write_ax25_header(&kiss_send_buffer);
  buffer_add(&kiss_send_buffer, ax25_test_payload, NELEMS(ax25_test_payload));
  kiss_write_buffer(fd_kiss, &kiss_send_buffer);
  buffer_clear(&kiss_send_buffer);

  uint8_t tmp_buffer[BUFFER_SIZE];
  while(true) {
    uint16_t capacity = buffer_capacity(&lithium_recv_buffer);
    int num_b_read = read(fd_lithium, tmp_buffer, capacity);
    buffer_add(&lithium_recv_buffer, tmp_buffer, num_b_read);

    if(cdi_check_packet(&lithium_recv_buffer)) {
      kiss_write_ax25_header(&kiss_send_buffer);
      kiss_write_ax25_payload(&kiss_send_buffer, &lithium_recv_buffer);
      kiss_write_buffer(fd_kiss, &kiss_send_buffer);
      buffer_clear(&kiss_send_buffer);
    }
  }

  return 0;
}
