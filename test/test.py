sum = 0
for i in range(1, 11):
    s = 1000 * ( 1 - 0.2 / 100 )
    sum += s
    if i % 3 == 0:
        print(f"第{i}期,\t实际金额: {s:.2f}元,\t合计: {sum:.2f}元")
    else:
        print(f"第{i}期,\t实际金额: {s:.2f}元,\t合计: {sum:.2f}元",end="\t")

print()

print(f"本金: 10000.00元, 与分期总金额差额: {(10000 - sum):.2f}元, 未分期实际金额: {10000 * ( 1 - 0.2 / 100 ):.2f}元, 费率: {0.2/100:.2%}")