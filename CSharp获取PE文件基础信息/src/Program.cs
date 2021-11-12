using System;
using System.Reflection.PortableExecutable;
using System.IO;
using Microsoft.Win32;

namespace CSharp获取PE基础信息
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("输入文件地址:");
            string FilePath = Console.ReadLine();
            FileStream fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read);
            //SectionHeader sch = new SectionHeader();

            PEReader pr = new PEReader(fs);
            Console.WriteLine("===================================== PE 头信息 ==================================");
            Console.Write("入口点    ：{0}\t\t", pr.PEHeaders.PEHeader.AddressOfEntryPoint.ToString("x8"));
            Console.WriteLine("子系统      ：{0}", pr.PEHeaders.PEHeader.Subsystem.ToString());
            Console.Write("镜像基址  ：{0}\t\t", pr.PEHeaders.PEHeader.ImageBase.ToString("x8"));
            Console.WriteLine("镜像大小    ：{0}", pr.PEHeaders.PEHeader.SizeOfImage.ToString("x8"));
            Console.Write("区段数    ：{0}\t\t\t", pr.PEHeaders.SectionHeaders.Length.ToString());
            Console.WriteLine("日期时间    ：{0}", pr.PEHeaders.CoffHeader.TimeDateStamp.ToString());
            Console.Write("代码基址  ：{0}\t\t", pr.PEHeaders.PEHeader.BaseOfCode.ToString("x8"));
            Console.WriteLine("头大小      ：{0}", pr.PEHeaders.PEHeader.SizeOfHeaders.ToString("x8"));
            Console.Write("数据基址  ：{0}\t\t", pr.PEHeaders.PEHeader.BaseOfData.ToString("x8"));
            Console.WriteLine("特征值      ：{0}", ((int)pr.PEHeaders.CoffHeader.Characteristics).ToString());
            Console.Write("块对齐    ：{0}\t\t", pr.PEHeaders.PEHeader.SectionAlignment.ToString("x8"));
            Console.WriteLine("校验和      ：{0}", pr.PEHeaders.PEHeader.CheckSum.ToString("x8"));
            Console.Write("标志字    ：{0}\t\t", pr.PEHeaders.PEHeader.Magic.ToString());
            Console.WriteLine("RVA大小     ：{0}", pr.PEHeaders.PEHeader.NumberOfRvaAndSizes.ToString("x8"));
            Console.Write("文件块对齐：{0}\t\t", pr.PEHeaders.PEHeader.FileAlignment.ToString("x8"));
            Console.WriteLine("可选头部大小：{0}", pr.PEHeaders.CoffHeader.SizeOfOptionalHeader.ToString("x8"));
            Console.WriteLine("===================================== 目录表 =====================================");
            Console.WriteLine("\t\t  RVA\t\t\t  Size");
            Console.WriteLine("输入表：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.ImportTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.ImportTableDirectory.Size.ToString("x8"));
            Console.WriteLine("导出表：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.ExportTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.ExportTableDirectory.Size.ToString("x8"));
            Console.WriteLine("资源表：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.ResourceTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.ResourceTableDirectory.Size.ToString("x8"));
            Console.WriteLine("异常表：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.ExceptionTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.ExceptionTableDirectory.Size.ToString("x8"));
            Console.WriteLine("证书表：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.CertificateTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.CertificateTableDirectory.Size.ToString("x8"));
            Console.WriteLine("重定位：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.BaseRelocationTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.BaseRelocationTableDirectory.Size.ToString("x8"));
            Console.WriteLine("调试表：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.DebugTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.DebugTableDirectory.Size.ToString("x8"));
            Console.WriteLine("版权表：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.CopyrightTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.CopyrightTableDirectory.Size.ToString("x8"));
            Console.WriteLine("全局指针：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.GlobalPointerTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.GlobalPointerTableDirectory.Size.ToString("x8"));
            Console.WriteLine("TLS表：\t\t{0}\t\t{1}", pr.PEHeaders.PEHeader.ThreadLocalStorageTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.ThreadLocalStorageTableDirectory.Size.ToString("x8"));
            Console.WriteLine("配置表：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.LoadConfigTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.LoadConfigTableDirectory.Size.ToString("x8"));
            Console.WriteLine("范围表：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.BoundImportTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.BoundImportTableDirectory.Size.ToString("x8"));
            Console.WriteLine("IAT表：\t\t{0}\t\t{1}", pr.PEHeaders.PEHeader.ImportAddressTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.ImportAddressTableDirectory.Size.ToString("x8"));
            Console.WriteLine("延迟输入：\t{0}\t\t{1}", pr.PEHeaders.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.DelayImportTableDirectory.Size.ToString("x8"));
            Console.WriteLine("COM表：\t\t{0}\t\t{1}", pr.PEHeaders.PEHeader.CorHeaderTableDirectory.RelativeVirtualAddress.ToString("x8"),
                pr.PEHeaders.PEHeader.CorHeaderTableDirectory.Size.ToString("x8"));
            Console.WriteLine("保留表(无)：\t00000000\t\t00000000");

            Console.WriteLine("===================================== 区段表 =====================================");
            Console.WriteLine("名称\tVOffset\t\tVSize\t\tROffset\t\tRSize\t\t标志");
            for (int i = 0; i < pr.PEHeaders.SectionHeaders.Length; i++)
            {
                Console.WriteLine("{0}\t{1}\t{2}\t{3}\t{4}\t{5}",
               pr.PEHeaders.SectionHeaders[i].Name.ToString(),
               pr.PEHeaders.SectionHeaders[i].VirtualAddress.ToString("x8"),
               pr.PEHeaders.SectionHeaders[i].VirtualSize.ToString("x8"),
               pr.PEHeaders.SectionHeaders[i].SizeOfRawData.ToString("x8"),
               pr.PEHeaders.SectionHeaders[i].PointerToRawData.ToString("x8"),
               ((uint)pr.PEHeaders.SectionHeaders[i].SectionCharacteristics).ToString("x8"));
            }


            Console.Read();
        }
    }
}
