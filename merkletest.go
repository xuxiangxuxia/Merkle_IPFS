package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	witness2 "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	r1cs2 "github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"log"
	"math"
	"sync"
	"time"
)

type MerkleProofCircuit struct {
	//LeafHash frontend.Variable `gnark:",public"` // 公开：待验证的叶子节点,由修改者发送
	//Leaf         []frontend.Variable
	Leaf         []frontend.Variable
	RootHash     frontend.Variable   `gnark:",public"` // 公开：Merkle 树的根哈希
	Path         []frontend.Variable // 私有：Merkle 路径哈希值
	LeafNum      []frontend.Variable //定义每个路径中的节点可以直接到达多少个叶子结点
	Helper       []frontend.Variable // 私有：路径中的辅助值，用来确定哈希方向（左右）
	LeafIndex    frontend.Variable   //当前叶子结点的索引值
	LeafNUm_byte []frontend.Variable // 私有：Merkle 路径的字节表示
}

func (circuit *MerkleProofCircuit) Define(api frontend.API) error {
	// 初始化 MiMC 哈希函数
	mimcHash, _ := mimc.NewMiMC(api)
	//mimc, _ := mimc.NewMiMC(api)

	// 开始验证 Merkle 路径
	computedLeaf := circuit.Leaf
	for i := 0; i < len(computedLeaf); i++ {
		mimcHash.Write(computedLeaf[i])
	}
	//mimcHash.Write(computedLeaf)
	computedHash := mimcHash.Sum()
	mimcHash.Reset()
	pathLen := len(circuit.Path)
	q := frontend.Variable(0)
	z := frontend.Variable(1) //当前计算节点的叶子结点数
	//api.Println("leafindex:", circuit.LeafIndex)

	for i := 0; i < pathLen; i++ {
		// 依次哈希路径中的每个节点
		pathHash := circuit.Path[i]
		helper := circuit.Helper[i]
		num := circuit.LeafNum[i]
		z = api.Add(z, num)

		// 如果 helper 为 1，表示 computedHash 是右节点，pathHash 是左节点
		// 如果 helper 为 0，表示 computedHash 是左节点，pathHash 是右节点
		// 创建两个哈希器，分别用于不同顺序的哈希计算
		// 当 helper 为 0 时，我们将 computedHash 作为左侧，pathHash 作为右侧
		mimcHash.Write(circuit.LeafNUm_byte[i], computedHash, pathHash)
		//mimcHash.Write(computedHash, pathHash)
		leftHash := mimcHash.Sum()
		mimcHash.Reset()

		// 当 helper 为 1 时，pathHash 作为左侧，computedHash 作为右侧
		mimcHash.Write(circuit.LeafNUm_byte[i], pathHash, computedHash)
		//mimcHash.Write(pathHash, computedHash)
		rightHash := mimcHash.Sum()
		mimcHash.Reset()

		// 使用 api.Select 来选择哪个哈希应该用于计算
		computedHash = api.Select(helper, rightHash, leftHash)
		q = api.Select(helper, api.Add(q, num), q)
		//api.Println("helper", helper)
		//api.Println("q", q)
		//computedHash = api.Select(helper, mimcHash.Hash(api, pathHash, computedHash), mimcHash.Hash(api, computedHash, pathHash))
	}

	// 最后，computedHash 应该等于 root
	api.AssertIsEqual(computedHash, circuit.RootHash)
	//api.Println("compute roothash:", computedHash)
	//api.Println(" roothash:", circuit.RootHash)
	api.AssertIsEqual(circuit.LeafIndex, q)
	//api.Println("q:", q)
	//api.Println(" index:", circuit.LeafIndex)

	return nil
}

// 定义哈希函数，使用 MIMC_BN254 进行哈希
func hashFunction(data []byte) []byte {
	// 初始化 MiMC 哈希函数
	hFunc := hash.MIMC_BN254.New()
	hFunc.Write(data)
	return hFunc.Sum(nil)
}

// 构造一棵 Merkle 树并生成验证路径
type MerkleTree struct {
	Leaves     [][]byte   // 原始叶子节点数据
	TreeLayers [][][]byte // Merkle 树的所有层，包括根节点
}

// 构建 Merkle 树
func (m *MerkleTree) BuildTree(path []int, path_byte [][]byte) {
	// 如果叶子节点数量是奇数，复制最后一个叶子节点以使数量为偶数
	if len(m.Leaves)%2 != 0 {
		m.Leaves = append(m.Leaves, m.Leaves[len(m.Leaves)-1])
	}

	// 第一层是叶子节点层
	hashedLeaves := make([][]byte, len(m.Leaves))
	for i, leaf := range m.Leaves {

		hashedLeaves[i] = hashFunction(leaf)
	}

	// 将叶子节点层添加到树层次中
	m.TreeLayers = append(m.TreeLayers, hashedLeaves)

	// 构建树的每一层，直到根节点
	currentLevel := hashedLeaves
	var index = 0
	for len(currentLevel) > 1 {
		var newLevel [][]byte
		for i := 0; i < len(currentLevel); i += 2 {
			combined := append(append(path_byte[index], currentLevel[i]...), currentLevel[i+1]...)
			//combined := append(currentLevel[i], currentLevel[i+1]...)
			combinedHash := hashFunction(combined)
			newLevel = append(newLevel, combinedHash)
		}

		// 如果新的一层节点数量是奇数，复制最后一个节点
		if len(newLevel)%2 != 0 && len(newLevel) != 1 {
			newLevel = append(newLevel, newLevel[len(newLevel)-1])
		}

		// 添加到树的层级
		m.TreeLayers = append(m.TreeLayers, newLevel)

		// 更新当前层为新的父层
		currentLevel = newLevel
		index++
	}
}

// 获取根哈希
func (m *MerkleTree) GetRoot() []byte {
	return m.TreeLayers[len(m.TreeLayers)-1][0] // 根节点为最后一层的第一个元素
}

// 获取指定叶子节点的证明路径
// level是索引越大，层数越高，倒序
// proof也是自底向上
func (m *MerkleTree) GetProof(leafIndex int) [][]byte {
	proof := [][]byte{}
	layerSize := len(m.Leaves)

	for level := 0; level < len(m.TreeLayers)-1; level++ {
		// 获取当前节点在该层的兄弟节点
		isRightNode := (leafIndex%2 == 1)
		siblingIndex := leafIndex - 1
		if isRightNode {
			siblingIndex = leafIndex - 1
		} else {
			siblingIndex = leafIndex + 1
		}

		// 确保兄弟节点在范围内
		if siblingIndex < layerSize {
			proof = append(proof, m.TreeLayers[level][siblingIndex])
		}

		// 准备进入上一层
		leafIndex /= 2
		layerSize = len(m.TreeLayers[level+1])
	}
	return proof
}

func verifyProof(wg *sync.WaitGroup, proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness2.Witness, resultChan chan<- bool) {
	defer wg.Done() // 确保在函数结束时调用Done()

	// 验证证明并将结果发送到通道
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		resultChan <- false
	} else {
		resultChan <- true
	}
}

func main() {

	// 示例数据：构建包含 4 个叶子节点的 Merkle 树
	mod := ecc.BN254.ScalarField()
	var leaves = make([][]byte, leafnum)
	for i := 0; i < len(leaves); i++ {
		leaf, _ := rand.Int(rand.Reader, mod)
		//assert.NoError(err)
		b := leaf.Bytes()
		if len(b) < dag_size {
			// 创建一个32字节的数组，并在前面填充零
			padded := make([]byte, dag_size)
			copy(padded[dag_size-len(b):], b)
			b = padded
		}
		leaves[i] = b
	}
	//计算z
	path, path_byte := calculateLeafNodesInPath(int(math.Log2(float64(len(leaves)))))
	//for i, p := range path {
	//	fmt.Printf("Step %d: %d\n", i+1, p)
	//	fmt.Printf("Step %d: %b\n", i+1, path_byte[i])
	//}

	// 创建 Merkle 树
	merkleTree := MerkleTree{Leaves: leaves}
	merkleTree.BuildTree(path, path_byte)

	// 输出 Merkle 根
	merkleRoot := merkleTree.GetRoot()
	fmt.Printf("Merkle Root: %x\n\n", merkleRoot)

	// 选择一个叶子节点并输出它的证明路径
	//leafIndex := 1 //
	proof := merkleTree.GetProof(leafIndex)
	fmt.Printf("Proof Path for leaf %d:\n", leafIndex)
	//for i, p := range proof {
	//	fmt.Printf("Step %d: %x\n", i+1, p)
	//}

	var circuit MerkleProofCircuit
	var assignment MerkleProofCircuit

	circuit.LeafIndex = leafIndex
	circuit.Path = make([]frontend.Variable, len(proof))
	circuit.Leaf = make([]frontend.Variable, len(leaves[leafIndex])/32)
	assignment.Leaf = make([]frontend.Variable, len(leaves[leafIndex])/32)
	circuit.LeafNum = make([]frontend.Variable, len(proof))
	circuit.Helper = make([]frontend.Variable, len(proof))
	circuit.LeafNUm_byte = make([]frontend.Variable, len(proof))
	var result = make([][]byte, len(leaves[leafIndex])/32)
	var index = 0
	for i := 0; i < len(leaves[leafIndex]); i += 32 {
		end := i + 32
		if end > len(leaves[leafIndex]) {
			end = len(leaves[leafIndex])
		}
		result[index] = leaves[leafIndex][i:end]
		circuit.Leaf[index] = result[index]
		assignment.Leaf[index] = result[index]
		index++
	}

	circuit.RootHash = merkleRoot
	for i := 0; i < len(proof); i++ {
		circuit.Path[i] = proof[i]
		circuit.LeafNum[i] = path[i]
		circuit.Helper[i] = leafIndex >> i & 1
		circuit.LeafNUm_byte[i] = path_byte[i]
		fmt.Printf("helper: %b\n", circuit.Helper[i])
		fmt.Printf("leafnum:%d\n", circuit.LeafNum[i])
		fmt.Printf("path:%x\n", circuit.Path[i])
		fmt.Printf("leaf_byte:%x\n", circuit.LeafNUm_byte[i])
	}

	t_compile := time.Now()
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs2.NewBuilder, &circuit)
	t_compile_end := time.Now()
	if err != nil {
		fmt.Printf("Compile failed : %v\n", err)
		return
	}
	log.Println("compile time: ", t_compile_end.Sub(t_compile))
	t_r1cs := time.Now()
	pk, vk, err := groth16.Setup(r1cs)
	t_r1cs_end := time.Now()
	if err != nil {
		fmt.Printf("Setup failed\n")
		return
	}
	log.Println("setup time: ", t_r1cs_end.Sub(t_r1cs))

	assignment.LeafIndex = leafIndex
	assignment.Path = make([]frontend.Variable, len(proof))
	//assignment.Leaf = leaves[leafIndex]
	assignment.LeafNum = make([]frontend.Variable, len(proof))
	assignment.Helper = make([]frontend.Variable, len(proof))
	assignment.LeafNUm_byte = make([]frontend.Variable, len(proof))
	assignment.RootHash = merkleRoot
	for i := 0; i < len(proof); i++ {
		assignment.Path[i] = proof[i]
		assignment.LeafNum[i] = path[i]
		assignment.Helper[i] = leafIndex >> i & 1
		assignment.LeafNUm_byte[i] = path_byte[i]
		fmt.Printf("helper %d: %b\n", i, assignment.Helper[i])
		fmt.Printf("leafnum %d: %d\n", i, assignment.LeafNum[i])
		fmt.Printf("proofpath %d: %x\n", i, assignment.Path[i])
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("witness:", err)
	}
	fmt.Printf("witness: %v\n", witness)

	//  批量生成witness
	publicWitness, err := witness.Public()
	//publicWitnessBytes, err := json.Marshal(publicWitness)
	//if err != nil {
	//	panic(err)
	//}
	//err = ioutil.WriteFile("public_input.json", publicWitnessBytes, 0644)
	//if err != nil {
	//	panic(err)
	//}
	publicWitnessgroup := make([]witness2.Witness, chalnum)
	for i := 0; i < chalnum; i++ {
		publicWitnessgroup[i] = publicWitness
	}

	var proofs []groth16.Proof

	t_zkProof := time.Now()
	//zkproof, err := groth16.Prove(r1cs, pk, witness)
	//批量生成证明，这里只用一条路径代替
	for i := 0; i < chalnum; i++ {
		zkproof, err := groth16.Prove(r1cs, pk, witness)
		proofs = append(proofs, zkproof)
		if err != nil {
			fmt.Printf("Prove failed： %v\n", err)
			return
		}
	}
	t_zkProof_end := time.Now()
	//if err != nil {
	//	fmt.Printf("Prove failed： %v\n", err)
	//	return
	//}
	log.Println("prove time: ", t_zkProof_end.Sub(t_zkProof))

	//publicWitness, err := witness.Public()
	////fmt.Println(err)
	//if err != nil {
	//	fmt.Println("public witness:", err)
	//}

	t_zkVerify := time.Now()
	// 使用goroutines并行验证
	var wg sync.WaitGroup
	resultChan := make(chan bool, len(proofs)) // 用于收集验证结果
	verified := true
	wg.Add(len(proofs))
	for i, proof := range proofs {
		go verifyProof(&wg, proof, vk, publicWitnessgroup[i], resultChan)
	}

	// 等待所有goroutines完成
	wg.Wait()
	close(resultChan)
	// 检查所有验证是否通过
	for result := range resultChan {
		if !result {
			verified = false
			break
		}
	}
	if verified {
		fmt.Println("所有证明验证通过")
	} else {
		fmt.Println("有证明验证失败")
	}
	t_zkVerify_end := time.Now()

	// 导出 Verification Key
	//vkBytes, err := json.Marshal(vk)
	//if err != nil {
	//	panic(err)
	//}
	//err = ioutil.WriteFile("vk.json", vkBytes, 0644)
	//if err != nil {
	//	panic(err)
	//}
	//
	//// 导出 Proof
	//proofBytes, err := json.Marshal(proof)
	//if err != nil {
	//	panic(err)
	//}
	//err = ioutil.WriteFile("proof.json", proofBytes, 0644)
	//if err != nil {
	//	panic(err)
	//}

	//// 导出 Public Input
	//publicWitness, err := witness.Public()
	//if err != nil {
	//	panic(err)
	//}

	//t_zkVerify := time.Now()
	//err = groth16.Verify(zkproof, vk, publicWitness)
	//t_zkVerify_end := time.Now()
	//if err != nil {
	//	fmt.Println("verify:", err)
	//}
	log.Println("verify time: ", t_zkVerify_end.Sub(t_zkVerify))

	//assert.ProverSucceeded(&mtCircuit, &witness, test.WithCurves(ecc.BN254))

}

// 计算路径中每个节点可到达的叶子结点个数
// 返回自底向上的数据
func calculateLeafNodesInPath(depth int) ([]int, [][]byte) {
	fmt.Println("Calculating the number of leaf nodes each node in the proof path can reach:")

	// Start at the leaf level
	//depth := len(proofPath) // The depth of the Merkle tree is determined by the proof path length
	currentLeaves := 1 // Each leaf node can reach only itself
	// Create an array to store the leaf counts
	leafCounts := make([]int, depth)
	leafcountbytres := make([][]byte, depth)

	for i := 0; i < depth; i++ { // Go from bottom (leaf) to top (root)
		fmt.Printf("Node at depth %d can reach %d leaf nodes\n", depth-i, currentLeaves)
		// Store the current leaf count at depth i
		leafCounts[i] = currentLeaves

		// 创建一个字节缓冲区
		buf := new(bytes.Buffer)

		// 将整数转换为大端序的字节并写入缓冲区
		err := binary.Write(buf, binary.BigEndian, int32(currentLeaves*2)) // 假设将 int 转为 int32
		if err != nil {
			fmt.Println("binary.Write failed:", err)
		}

		leafcountbytres[i] = hashFunction(buf.Bytes())

		currentLeaves *= 2

	}
	return leafCounts, leafcountbytres
}
