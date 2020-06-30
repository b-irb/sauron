unsigned int select_bit(unsigned int position, unsigned int bit_vector) {
    return bit_vector & (1 << position);
}
